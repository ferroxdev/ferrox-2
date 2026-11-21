//! A macOS TAP is a `feth` pair that carries Ethernet frames, so the IP handler keeps its packet
//! path and this bridge answers ARP and IPv6 neighbour solicitation, strips the link header on
//! read and writes it back on emit.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

pub(crate) const HEADER_LEN: usize = 14;
const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86dd;
const ARP: u16 = 0x0806;
const ICMPV6: u8 = 58;
const NEIGHBOR_SOLICITATION: u8 = 135;
const NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// One frame from the device: an IP packet for the handler, an answer the bridge writes back, or
/// a frame it drops.
pub(crate) enum Accepted<'a> {
    Ip(&'a [u8]),
    Reply(Vec<u8>),
    Ignore,
}

/// The link side of one TAP: the addresses this side answers for, the addresses the host already
/// holds, and the peer's address once a frame names it.
pub(crate) struct Bridge {
    local: [u8; 6],
    addresses: Vec<IpAddr>,
    host: Vec<IpAddr>,
    /// A captured route with no gateway treats every destination as on-link, so the bridge answers
    /// ARP and neighbour solicitation for the addresses it does not carry too.
    proxy: bool,
    peer: Mutex<Option<[u8; 6]>>,
}

impl Bridge {
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn new(name: &str, addresses: Vec<IpAddr>, host: Vec<IpAddr>, proxy: bool) -> Self {
        Self {
            local: local_address(name),
            addresses,
            host,
            proxy,
            peer: Mutex::new(None),
        }
    }

    fn peer(&self) -> Option<[u8; 6]> {
        *self
            .peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn learn(&self, address: [u8; 6]) {
        let mut peer = self
            .peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *peer = Some(address);
    }

    /// One Ethernet frame: an IP packet the handler may take, an ARP or neighbour answer to write
    /// back, or a frame the bridge drops.
    pub(crate) fn accept<'a>(&self, frame: &'a [u8]) -> Accepted<'a> {
        if frame.len() < HEADER_LEN {
            return Accepted::Ignore;
        }
        let destination = &frame[..6];
        let mut source = [0u8; 6];
        source.copy_from_slice(&frame[6..12]);
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let body = &frame[HEADER_LEN..];
        let accepted = match ethertype {
            IPV4 if destination == self.local => Accepted::Ip(body),
            IPV6 if destination == self.local
                || (destination[0] & 1 == 1
                    && solicited_mac(body).is_some_and(|mac| mac == destination)) =>
            {
                if destination == self.local && Self::invalid_solicitation(body) {
                    return Accepted::Ignore;
                }
                match self.neighbour_advertisement(body, source) {
                    Some(reply) => Accepted::Reply(reply),
                    None if destination == self.local && !Self::solicitation(body) => {
                        Accepted::Ip(body)
                    }
                    None => Accepted::Ignore,
                }
            }
            ARP if destination[0] & 1 == 1 || destination == self.local => {
                match self.arp_reply(body, source) {
                    Some(reply) => Accepted::Reply(reply),
                    None => Accepted::Ignore,
                }
            }
            _ => Accepted::Ignore,
        };
        if !matches!(accepted, Accepted::Ignore) && source != self.local && source[0] & 1 == 0 {
            self.learn(source);
        }
        accepted
    }

    /// Frame one IP packet for the peer the device last named, or for broadcast until a frame has
    /// named it.
    pub(crate) fn frame(&self, packet: &[u8], out: &mut Vec<u8>) -> bool {
        let ethertype = match packet.first().map(|byte| byte >> 4) {
            Some(4) => IPV4,
            Some(6) => IPV6,
            _ => return false,
        };
        out.clear();
        out.extend_from_slice(&self.peer().unwrap_or([0xff; 6]));
        out.extend_from_slice(&self.local);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(packet);
        true
    }

    fn arp_reply(&self, body: &[u8], peer: [u8; 6]) -> Option<Vec<u8>> {
        if body.len() < 28
            || u16::from_be_bytes([body[0], body[1]]) != 1
            || u16::from_be_bytes([body[2], body[3]]) != IPV4
            || body[4] != 6
            || body[5] != 4
            || u16::from_be_bytes([body[6], body[7]]) != 1
        {
            return None;
        }
        let asked = Ipv4Addr::new(body[24], body[25], body[26], body[27]);
        let probe = body[14..18] == [0, 0, 0, 0];
        let announcement = body[14..18] == asked.octets();
        // A probe or announcement for an address the host holds would make the host see a conflicting MAC.
        let host_holds = self
            .host
            .iter()
            .any(|address| matches!(address, IpAddr::V4(v4) if *v4 == asked));
        if host_holds && (probe || announcement) {
            return None;
        }
        let owned = self
            .addresses
            .iter()
            .any(|address| matches!(address, IpAddr::V4(v4) if *v4 == asked));
        if (probe && !owned) || (!self.proxy && !owned) {
            return None;
        }
        let mut out = Vec::with_capacity(HEADER_LEN + 28);
        out.extend_from_slice(&peer);
        out.extend_from_slice(&self.local);
        out.extend_from_slice(&ARP.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
        out.extend_from_slice(&self.local);
        out.extend_from_slice(&asked.octets());
        out.extend_from_slice(&peer);
        out.extend_from_slice(&body[14..18]);
        Some(out)
    }

    /// Whether the packet is an ICMPv6 Neighbor Solicitation, whatever its checksum or hop limit.
    fn solicitation(body: &[u8]) -> bool {
        body.len() >= 48
            && body[0] >> 4 == 6
            && body[6] == ICMPV6
            && body[40] == NEIGHBOR_SOLICITATION
    }

    fn invalid_solicitation(body: &[u8]) -> bool {
        if body.len() < 40 || body[0] >> 4 != 6 || body[6] != ICMPV6 {
            return false;
        }
        let message = &body[40..];
        if message.len() < 8 || message[0] != NEIGHBOR_SOLICITATION {
            return false;
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&body[8..24]).unwrap_or_default());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&body[24..40]).unwrap_or_default());
        icmpv6_checksum(&source, &destination, message) != 0
    }

    fn neighbour_advertisement(&self, body: &[u8], peer: [u8; 6]) -> Option<Vec<u8>> {
        if body.len() < 40 + 24 || body[0] >> 4 != 6 || body[6] != ICMPV6 || body[7] != 255 {
            return None;
        }
        let payload = usize::from(u16::from_be_bytes([body[4], body[5]]));
        if body.len() != 40 + payload {
            return None;
        }
        let message = &body[40..];
        if message[0] != NEIGHBOR_SOLICITATION || message[1] != 0 {
            return None;
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&body[8..24]).ok()?);
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&body[24..40]).ok()?);
        if source.is_multicast() || icmpv6_checksum(&source, &destination, message) != 0 {
            return None;
        }
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&message[8..24]).ok()?);
        if target.is_unspecified()
            || target.is_multicast()
            || !solicitation_options_ok(&message[24..], source.is_unspecified())
        {
            return None;
        }
        if source.is_unspecified() && destination != solicited_node(target) {
            return None;
        }
        let owned = self
            .addresses
            .iter()
            .any(|address| matches!(address, IpAddr::V6(v6) if *v6 == target));
        // A duplicate-address probe is never answered for an address the host already holds; a proxy reply to a target it does not carry would make a host reject a fresh address.
        if source.is_unspecified() && (!owned || self.host.contains(&IpAddr::V6(target))) {
            return None;
        }
        if !owned && !self.proxy {
            return None;
        }
        // RFC 4861: a solicitation from the unspecified source is answered to all-nodes with the solicited flag clear. A proxy answer for an address this bridge does not own leaves override clear so the real owner's advertisement wins.
        let (destination, destination_mac, flags) = if source.is_unspecified() {
            (
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                [0x33, 0x33, 0, 0, 0, 1],
                [0x20, 0, 0, 0],
            )
        } else {
            (
                source,
                peer,
                if owned {
                    [0x60, 0, 0, 0]
                } else {
                    [0x40, 0, 0, 0]
                },
            )
        };
        let mut answer = Vec::with_capacity(32);
        answer.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT, 0, 0, 0]);
        answer.extend_from_slice(&flags);
        answer.extend_from_slice(&target.octets());
        answer.extend_from_slice(&[2, 1]);
        answer.extend_from_slice(&self.local);
        let reply_source = if owned || source.is_unspecified() {
            target
        } else {
            self.addresses
                .iter()
                .find_map(|address| match address {
                    std::net::IpAddr::V6(address) => Some(*address),
                    std::net::IpAddr::V4(_) => None,
                })
                .unwrap_or(target)
        };
        let checksum = icmpv6_checksum(&reply_source, &destination, &answer);
        answer[2..4].copy_from_slice(&checksum.to_be_bytes());
        frame_ipv6(
            destination_mac,
            self.local,
            reply_source,
            destination,
            &answer,
        )
    }
}

/// Walk the solicitation's options: each length is in eight-byte units, must be non-zero, and must
/// stay inside the message. A probe from the unspecified source may not carry its own link address.
fn solicitation_options_ok(mut options: &[u8], source_unspecified: bool) -> bool {
    while !options.is_empty() {
        if options.len() < 2 {
            return false;
        }
        let len = usize::from(options[1]) * 8;
        if len == 0 || len > options.len() || (source_unspecified && options[0] == 1) {
            return false;
        }
        options = &options[len..];
    }
    true
}

/// The Ethernet multicast address for a solicitation's target, so a bridge answers only the group it was addressed to.
fn solicited_mac(body: &[u8]) -> Option<[u8; 6]> {
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(body.get(48..64)?).ok()?);
    let octets = target.octets();
    Some([0x33, 0x33, 0xff, octets[13], octets[14], octets[15]])
}

/// The solicited-node multicast address of `target`, the only destination a DAD probe may use.
fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
    let octets = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(octets[13]),
        (u16::from(octets[14]) << 8) | u16::from(octets[15]),
    )
}

/// A locally administered unicast address derived from the interface name, so a restart claims the
/// same address; the host's neighbour cache follows this answer, not the feth's own address.
#[cfg(any(target_os = "macos", test))]
fn local_address(seed: &str) -> [u8; 6] {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seed.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let bytes = hash.to_be_bytes();
    [0x02, 0xfe, bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn frame_ipv6(
    destination: [u8; 6],
    source: [u8; 6],
    from: Ipv6Addr,
    to: Ipv6Addr,
    message: &[u8],
) -> Option<Vec<u8>> {
    let length = u16::try_from(message.len()).ok()?;
    let mut out = Vec::with_capacity(HEADER_LEN + 40 + message.len());
    out.extend_from_slice(&destination);
    out.extend_from_slice(&source);
    out.extend_from_slice(&IPV6.to_be_bytes());
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&length.to_be_bytes());
    out.push(ICMPV6);
    out.push(255);
    out.extend_from_slice(&from.octets());
    out.extend_from_slice(&to.octets());
    out.extend_from_slice(message);
    Some(out)
}

/// The `ICMPv6` checksum over the IPv6 pseudo-header and the message.
fn icmpv6_checksum(source: &Ipv6Addr, destination: &Ipv6Addr, message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for octets in [source.octets(), destination.octets()] {
        let (pairs, _) = octets.as_chunks::<2>();
        for pair in pairs {
            sum += u32::from(u16::from_be_bytes(*pair));
        }
    }
    sum += u32::from(u16::try_from(message.len()).unwrap_or(u16::MAX));
    sum += u32::from(ICMPV6);
    let (words, rest) = message.as_chunks::<2>();
    for pair in words {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(destination: [u8; 6], source: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&destination);
        frame.extend_from_slice(&source);
        frame.extend_from_slice(&IPV4.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn arp_request(peer: [u8; 6], asked: Ipv4Addr, from: Ipv4Addr) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&ARP.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&from.octets());
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&asked.octets());
        frame
    }

    #[test]
    fn a_tap_reads_an_ip_packet_and_frames_the_answer_for_the_peer_it_learned() {
        let bridge = Bridge::new(
            "feth0",
            vec!["10.0.0.1".parse().unwrap()],
            Vec::new(),
            false,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let payload = [0x45, 0, 0, 20];
        let frame = ipv4_frame(bridge.local, peer, &payload);
        match bridge.accept(&frame) {
            Accepted::Ip(read) => assert_eq!(read, payload),
            _ => panic!("an IP packet addressed to the device is read"),
        }
        let mut out = Vec::new();
        assert!(bridge.frame(&payload, &mut out));
        assert_eq!(&out[..6], &peer, "the answer goes to the peer's address");
        assert_eq!(&out[6..12], &bridge.local, "and comes from the device's");
        assert_eq!(&out[12..14], &IPV4.to_be_bytes());
        assert_eq!(&out[14..], payload);
    }

    #[test]
    fn a_tap_answers_an_arp_request_for_an_address_it_carries_and_ignores_another() {
        let bridge = Bridge::new(
            "feth0",
            vec!["10.0.0.1".parse().unwrap()],
            Vec::new(),
            false,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let Accepted::Reply(reply) = bridge.accept(&arp_request(
            peer,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.9".parse().unwrap(),
        )) else {
            panic!("its own address is answered");
        };
        assert_eq!(&reply[..6], &peer);
        assert_eq!(&reply[6..12], &bridge.local);
        assert_eq!(&reply[12..14], &ARP.to_be_bytes());
        assert_eq!(&reply[14..22], &[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
        assert_eq!(
            &reply[22..28],
            &bridge.local,
            "sender hardware is the device"
        );
        assert_eq!(
            &reply[28..32],
            &"10.0.0.1".parse::<Ipv4Addr>().unwrap().octets()
        );
        assert_eq!(&reply[32..38], &peer, "target hardware is the asker");
        assert_eq!(
            &reply[38..42],
            &"10.0.0.9".parse::<Ipv4Addr>().unwrap().octets()
        );
        let other = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10];
        assert!(
            matches!(
                bridge.accept(&arp_request(
                    other,
                    "10.0.0.2".parse().unwrap(),
                    "10.0.0.9".parse().unwrap()
                )),
                Accepted::Ignore
            ),
            "an address the device does not carry is left to its owner"
        );
        let mut out = Vec::new();
        assert!(bridge.frame(&[0x45, 0, 0, 20], &mut out));
        assert_eq!(
            &out[..6],
            &peer,
            "an ignored frame does not replace the peer"
        );
    }

    #[test]
    fn a_tap_leaves_the_hosts_gratuitous_arp_to_the_host() {
        let bridge = Bridge::new(
            "feth0",
            vec!["10.0.0.1".parse().unwrap()],
            vec!["10.0.0.1".parse().unwrap()],
            true,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        assert!(
            matches!(
                bridge.accept(&arp_request(
                    peer,
                    "10.0.0.1".parse().unwrap(),
                    "10.0.0.1".parse().unwrap()
                )),
                Accepted::Ignore
            ),
            "an announcement for an address the host holds is not answered"
        );
    }

    #[test]
    fn a_tap_does_not_proxy_an_arp_probe_for_a_free_address() {
        let bridge = Bridge::new("feth0", vec!["10.0.0.1".parse().unwrap()], Vec::new(), true);
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        assert!(
            matches!(
                bridge.accept(&arp_request(
                    peer,
                    "10.0.0.2".parse().unwrap(),
                    "0.0.0.0".parse().unwrap()
                )),
                Accepted::Ignore
            ),
            "a probe for an address the bridge does not carry is left to its owner"
        );
        let Accepted::Reply(_) = bridge.accept(&arp_request(
            peer,
            "10.0.0.2".parse().unwrap(),
            "10.0.0.9".parse().unwrap(),
        )) else {
            panic!("an ordinary lookup for a free address is still proxied");
        };
    }

    #[test]
    fn a_tap_answers_a_neighbour_solicitation_with_a_checked_advertisement() {
        let bridge = Bridge::new(
            "feth0",
            vec!["2001:db8::1".parse().unwrap(), "10.0.0.1".parse().unwrap()],
            Vec::new(),
            false,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let asker: Ipv6Addr = "fe80::9".parse().unwrap();
        let frame = ns_frame(peer, asker, target);
        let Accepted::Reply(reply) = bridge.accept(&frame) else {
            panic!("a solicitation for its address is answered");
        };
        assert_eq!(&reply[..6], &peer);
        assert_eq!(&reply[6..12], &bridge.local);
        assert_eq!(&reply[12..14], &IPV6.to_be_bytes());
        assert_eq!(reply[14] >> 4, 6);
        assert_eq!(reply[20], ICMPV6);
        assert_eq!(reply[21], 255);
        assert_eq!(&reply[22..38], &target.octets(), "the answer names itself");
        assert_eq!(&reply[38..54], &asker.octets());
        let message = &reply[54..];
        assert_eq!(message[0], NEIGHBOR_ADVERTISEMENT);
        assert_eq!(&message[4..8], &[0x60, 0, 0, 0]);
        assert_eq!(&message[8..24], &target.octets());
        assert_eq!(&message[24..26], &[2, 1]);
        assert_eq!(&message[26..32], &bridge.local);
        let seen = icmpv6_checksum(&target, &asker, message);
        assert_eq!(
            seen, 0,
            "the advertisement's checksum verifies over its own header"
        );
    }

    fn ns_frame(peer: [u8; 6], source: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
        let octets = target.octets();
        ns_frame_to(
            peer,
            source,
            target,
            Ipv6Addr::new(
                0xff02,
                0,
                0,
                0,
                0,
                1,
                0xff00 | u16::from(octets[13]),
                (u16::from(octets[14]) << 8) | u16::from(octets[15]),
            ),
            [0x33, 0x33, 0xff, octets[13], octets[14], octets[15]],
        )
    }

    fn ns_frame_to(
        peer: [u8; 6],
        source: Ipv6Addr,
        target: Ipv6Addr,
        destination: Ipv6Addr,
        destination_mac: [u8; 6],
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(24);
        message.extend_from_slice(&[NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(&target.octets());
        let checksum = icmpv6_checksum(&source, &destination, &message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut frame = Vec::new();
        frame.extend_from_slice(&destination_mac);
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&IPV6.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(&24u16.to_be_bytes());
        frame.extend_from_slice(&[ICMPV6, 255]);
        frame.extend_from_slice(&source.octets());
        frame.extend_from_slice(&destination.octets());
        frame.extend_from_slice(&message);
        frame
    }

    fn ns_frame_with_options(
        peer: [u8; 6],
        source: Ipv6Addr,
        target: Ipv6Addr,
        options: &[u8],
    ) -> Vec<u8> {
        let destination = solicited_node(target);
        let mut message = Vec::with_capacity(24 + options.len());
        message.extend_from_slice(&[NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(&target.octets());
        message.extend_from_slice(options);
        let checksum = icmpv6_checksum(&source, &destination, &message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut frame = Vec::new();
        frame.extend_from_slice(&destination_mac(destination));
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&IPV6.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
        frame.extend_from_slice(&[ICMPV6, 255]);
        frame.extend_from_slice(&source.octets());
        frame.extend_from_slice(&destination.octets());
        frame.extend_from_slice(&message);
        frame
    }

    fn destination_mac(destination: Ipv6Addr) -> [u8; 6] {
        let octets = destination.octets();
        [0x33, 0x33, octets[12], octets[13], octets[14], octets[15]]
    }

    #[test]
    fn a_tap_answers_a_unicast_solicitation_and_a_proxy_one_for_an_address_it_does_not_carry() {
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let own: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let asker: Ipv6Addr = "fe80::9".parse().unwrap();
        let bridge = Bridge::new("feth0", vec![IpAddr::V6(own)], Vec::new(), true);
        assert!(
            matches!(
                bridge.accept(&ns_frame_to(peer, asker, own, own, bridge.local)),
                Accepted::Reply(_)
            ),
            "a solicitation addressed to the device's own address is still answered"
        );
        assert!(
            matches!(
                bridge.accept(&ns_frame_to(peer, asker, own, own, peer)),
                Accepted::Ignore
            ),
            "a solicitation to another unicast MAC is left alone"
        );
        assert!(
            matches!(
                bridge.accept(&ns_frame(
                    peer,
                    asker,
                    "2001:4860:4860::8888".parse().unwrap()
                )),
                Accepted::Reply(_)
            ),
            "a captured route makes every destination on-link, so the proxy answers for it"
        );
        let single = Bridge::new("feth0", vec![IpAddr::V6(own)], Vec::new(), false);
        assert!(
            matches!(
                single.accept(&ns_frame(peer, asker, "2001:db8::2".parse().unwrap())),
                Accepted::Ignore
            ),
            "without capture an address the device does not carry is left alone"
        );
    }

    #[test]
    fn a_tap_leaves_a_duplicate_probe_for_the_hosts_address_to_the_host() {
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let held = Bridge::new(
            "feth0",
            vec![IpAddr::V6(target)],
            vec![IpAddr::V6(target)],
            false,
        );
        assert!(
            matches!(
                held.accept(&ns_frame(peer, Ipv6Addr::UNSPECIFIED, target)),
                Accepted::Ignore
            ),
            "the host's own probe must not see a competing advertisement"
        );
        let claimed = Bridge::new("feth0", vec![IpAddr::V6(target)], Vec::new(), false);
        let Accepted::Reply(reply) = claimed.accept(&ns_frame(peer, Ipv6Addr::UNSPECIFIED, target))
        else {
            panic!("a probe for a bridge-only address is still a solicitation");
        };
        assert_eq!(
            &reply[..6],
            &[0x33, 0x33, 0, 0, 0, 1],
            "the answer is multicast"
        );
        let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
        assert_eq!(&reply[38..54], &all_nodes.octets());
        assert_eq!(&reply[54..56], &[NEIGHBOR_ADVERTISEMENT, 0]);
        assert_eq!(
            &reply[58..62],
            &[0x20, 0, 0, 0],
            "the solicited flag is clear"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs root for a feth pair; ci.yml runs it under sudo"]
    fn a_real_feth_pair_carries_an_arp_request_to_the_bridge() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let base = 2000 + (std::process::id() % 500) as usize;
        let name = format!("feth{base}");
        let peer = format!("feth{}", base + 1);
        let target = format!("198.18.1.{}", base % 250 + 1);
        let spec = crate::tun::Spec::new(Some(&name), Some(1500))
            .with_addresses(vec![("198.18.0.1".parse().unwrap(), 15)])
            .with_tap(true, Some(&peer));
        let (device, _, _) =
            crate::tun_stack::build(&spec, false, false).expect("open a real feth pair");
        let device_name = device.name().expect("the device names its half");
        let bridge = Bridge::new(
            &device_name,
            vec!["198.18.0.1".parse().unwrap()],
            Vec::new(),
            true,
        );
        for interface in [&device_name, &peer] {
            let status = Command::new("ifconfig")
                .args([interface.as_str(), "up"])
                .status()
                .expect("bring the feth pair up");
            assert!(status.success(), "ifconfig {interface} up failed: {status}");
        }
        device.set_nonblocking(true).expect("poll the device");
        let mut ping = Command::new("ping")
            .args([
                "-n",
                "-c",
                "1",
                "-t",
                "1",
                "-b",
                &device_name,
                "-S",
                "198.18.0.1",
                target.as_str(),
            ])
            .spawn()
            .expect("ping the peer");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 2048];
        let asked: Ipv4Addr = target.parse().expect("target");
        let mut source: Option<[u8; 4]> = None;
        let mut answered = false;
        while Instant::now() < deadline && !answered {
            match device.recv(&mut buf) {
                Ok(n) => {
                    let frame = &buf[..n];
                    if frame.len() >= 42
                        && u16::from_be_bytes([frame[12], frame[13]]) == ARP
                        && u16::from_be_bytes([frame[20], frame[21]]) == 1
                        && frame[38..42] == asked.octets()
                    {
                        source = <[u8; 4]>::try_from(&frame[28..32]).ok();
                    }
                    match bridge.accept(frame) {
                        Accepted::Reply(reply) => {
                            assert_eq!(u16::from_be_bytes([reply[12], reply[13]]), ARP);
                            assert_eq!(reply[20..22], [0, 2], "an ARP reply");
                            eprintln!(
                                "arp reply sender {:?} target {:?} expected {:?}",
                                &reply[28..32],
                                &reply[38..42],
                                source
                            );
                            if reply[28..32] == asked.octets()
                                && source.is_some_and(|source| reply[38..42] == source)
                            {
                                device.send(&reply).expect("write the reply to the peer");
                                answered = true;
                            }
                        }
                        Accepted::Ip(_) | Accepted::Ignore => {}
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("read the feth peer: {error}"),
            }
        }
        let status = ping.wait().expect("the probe exits");
        assert!(
            answered,
            "the kernel's ARP request reached the bridge (source {source:?}, ping {status})"
        );
    }

    #[test]
    fn a_dad_probe_may_not_carry_its_own_link_address() {
        let bridge = Bridge::new(
            "feth0",
            vec!["2001:db8::1".parse().unwrap()],
            Vec::new(),
            true,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let probe = ns_frame_with_options(
            peer,
            Ipv6Addr::UNSPECIFIED,
            target,
            &[1, 1, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        );
        assert!(matches!(bridge.accept(&probe), Accepted::Ignore));
    }

    #[test]
    fn a_tap_validates_a_solicitation_before_answering_it() {
        let bridge = Bridge::new(
            "feth0",
            vec!["2001:db8::1".parse().unwrap()],
            Vec::new(),
            true,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let asker: Ipv6Addr = "fe80::9".parse().unwrap();
        let mut bad = ns_frame(peer, asker, target);
        bad[21] = 64;
        assert!(matches!(bridge.accept(&bad), Accepted::Ignore));
        let mut bad = ns_frame(peer, asker, target);
        bad[56] ^= 0xff;
        assert!(matches!(bridge.accept(&bad), Accepted::Ignore));
        assert!(matches!(
            bridge.accept(&ns_frame(
                peer,
                Ipv6Addr::UNSPECIFIED,
                "2001:db8::2".parse().unwrap()
            )),
            Accepted::Ignore
        ));
        let mut unicast = ns_frame_to(peer, asker, target, target, bridge.local);
        unicast[56] ^= 0xff;
        assert!(matches!(bridge.accept(&unicast), Accepted::Ignore));
        assert!(
            bridge.peer().is_none(),
            "an invalid solicitation learns nothing"
        );
    }

    #[test]
    fn a_proxy_advertisement_for_an_address_it_does_not_own_leaves_override_clear() {
        let bridge = Bridge::new(
            "feth0",
            vec!["2001:db8::1".parse().unwrap()],
            Vec::new(),
            true,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let asker: Ipv6Addr = "fe80::9".parse().unwrap();
        let target: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let Accepted::Reply(reply) = bridge.accept(&ns_frame(peer, asker, target)) else {
            panic!("the proxy answers for a captured target");
        };
        assert_eq!(&reply[58..62], &[0x40, 0, 0, 0]);
    }

    #[test]
    fn a_tap_leaves_a_frame_for_another_address_alone() {
        let bridge = Bridge::new(
            "feth0",
            vec!["10.0.0.1".parse().unwrap()],
            Vec::new(),
            false,
        );
        let peer = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let frame = ipv4_frame([0x02, 0, 0, 0, 0, 1], peer, &[0x45, 0, 0, 20]);
        assert!(matches!(bridge.accept(&frame), Accepted::Ignore));
        assert!(
            !bridge.frame(&[0x88, 0, 0, 0], &mut Vec::new()),
            "a packet that is not IP is not framed"
        );
    }
}
