//! The TUN inbound: `tun-rs` carries the kernel device, batching a queue's
//! packets with GSO/GRO, and the `WireGuard` server stack owns the TCP state
//! machine and the per-flow proxy dial. Every queue is one stack, one reader
//! and one writer, so a multi-queue device spreads flows across cores without a
//! lock between them. The `system` and `hybrid` names hand TCP to the kernel
//! stack through a NAT loop on Linux instead; hybrid falls back to this stack
//! for a flow the kernel cannot take.

use std::io;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
)))]
use tun_rs::DeviceBuilder;
use tun_rs::SyncDevice;

#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use crate::proxy::Outbound;
use crate::tun::Spec;
use crate::wg_stack::Packet;
use crate::wireguard::DeviceConfig;

pub(crate) const RX_QUEUE: usize = 1024;
pub(crate) const TX_QUEUE: usize = 1024;
/// The most packets one write batches; 32 packets fill one 64 KiB aggregate.
#[cfg(target_os = "linux")]
const WRITE_BATCH: usize = 64;

#[cfg(unix)]
pub(crate) type WakeWriter = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
pub(crate) type WakeWriter = ();

/// Wait for a removable queue to carry a packet, so its stop flag is seen on an idle device.
#[cfg(unix)]
fn wait_readable(device: &SyncDevice, budget: std::time::Duration) -> io::Result<bool> {
    let mut row = libc::pollfd {
        fd: device.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = i32::try_from(budget.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: one descriptor the device owns, one array element, and `poll` writes only `revents`.
    let ready = unsafe { libc::poll(&raw mut row, 1, millis) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    if ready == 0 {
        return Ok(false);
    }
    let terminal = row.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL);
    if terminal != 0 && row.revents & libc::POLLIN == 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "the tun device reported a terminal event",
        ));
    }
    Ok(row.revents & libc::POLLIN != 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Userspace,
    System,
    Hybrid,
}

/// Open the device and start the configured TCP stack, returning the interface the platform gave it so a route can name it and the workers a removable inbound must join.
pub(crate) fn serve(
    spec: &Spec,
    out: &Outbound,
    mode: Mode,
    stopping: Option<&Arc<AtomicBool>>,
) -> io::Result<(String, Option<Vec<thread::JoinHandle<()>>>)> {
    match mode {
        Mode::Userspace => serve_userspace(spec, out, stopping),
        #[cfg(target_os = "linux")]
        Mode::System => crate::tun_system::serve(spec, out, false, stopping)
            .map(|(name, workers)| (name, Some(workers))),
        #[cfg(target_os = "linux")]
        Mode::Hybrid => match crate::tun_system::serve(spec, out, true, stopping) {
            Ok((name, workers)) => Ok((name, Some(workers))),
            Err(error) => {
                eprintln!(
                    "tun inbound: the hybrid stack is unavailable ({error}), using the userspace stack"
                );
                serve_userspace(spec, out, stopping)
            }
        },
        #[cfg(not(target_os = "linux"))]
        Mode::System => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the system tun stack is Linux-only",
        )),
        #[cfg(not(target_os = "linux"))]
        Mode::Hybrid => {
            eprintln!("tun inbound: the hybrid stack is Linux-only, using the userspace stack");
            serve_userspace(spec, out, stopping)
        }
    }
}

fn serve_userspace(
    spec: &Spec,
    out: &Outbound,
    stopping: Option<&Arc<AtomicBool>>,
) -> io::Result<(String, Option<Vec<thread::JoinHandle<()>>>)> {
    let (first, offload, queues) = open(spec)?;
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    )))]
    let name = first.name()?;
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    ))]
    let name = String::new();
    let first = Arc::new(first);
    #[cfg(target_os = "linux")]
    let mut devices = vec![Arc::clone(&first)];
    #[cfg(not(target_os = "linux"))]
    let devices = vec![Arc::clone(&first)];
    #[cfg(target_os = "linux")]
    for _ in 1..queues {
        devices.push(Arc::new(first.try_clone()?));
    }
    #[cfg(target_os = "linux")]
    if stopping.is_some() {
        for device in &devices {
            device.set_nonblocking(true)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = queues;
    let mut workers = Vec::with_capacity(devices.len());
    for device in devices {
        workers.extend(spawn_queue(
            device,
            spec,
            offload,
            out.clone(),
            stopping.cloned(),
        ));
    }
    Ok((name, Some(workers)))
}

#[cfg(target_os = "macos")]
fn feth_peer(device: &str) -> io::Result<String> {
    let output = std::process::Command::new("/sbin/ifconfig")
        .arg(device)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("`ifconfig {device}` failed")));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let peer = line.trim().strip_prefix("peer:")?.trim();
            (!peer.is_empty() && peer != "<none>").then(|| peer.to_owned())
        })
        .ok_or_else(|| io::Error::other(format!("the TAP device {device} names no peer")))
}

fn open(spec: &Spec) -> io::Result<(SyncDevice, bool, usize)> {
    #[cfg(target_os = "linux")]
    {
        let multi = spec.queues() > 1;
        match build(spec, multi, spec.gso()) {
            Ok((device, offload, multi)) => {
                Ok((device, offload, if multi { spec.queues() } else { 1 }))
            }
            Err(error) => {
                if let Ok((device, offload, multi)) = build(spec, multi, false) {
                    return Ok((device, offload, if multi { spec.queues() } else { 1 }));
                }
                if multi && let Ok((device, offload, _)) = build(spec, false, spec.gso()) {
                    return Ok((device, offload, 1));
                }
                if let Ok((device, offload, _)) = build(spec, false, false) {
                    return Ok((device, offload, 1));
                }
                Err(error)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (device, _, _) = build(spec, false, false)?;
        Ok((device, false, 1))
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
)))]
pub(crate) fn build(
    spec: &Spec,
    multi: bool,
    offload: bool,
) -> io::Result<(SyncDevice, bool, bool)> {
    spec.validate()?;
    let mtu = u16::try_from(spec.mtu()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tun mtu {} exceeds 65535", spec.mtu()),
        )
    })?;
    // An empty name lets the platform pick (`utunN` on macOS); a named device keeps the same interface across restarts.
    let mut builder = DeviceBuilder::new().mtu(mtu);
    if !spec.name().is_empty() {
        builder = builder.name(spec.name());
    }
    // The builder carries the first IPv4 and nothing else, so an address it refuses is a line from `attach_addresses` rather than a failed open.
    let mut extra = Vec::new();
    let mut primary = false;
    for (address, prefix) in spec.addresses() {
        match address {
            IpAddr::V4(address) if !primary => {
                builder = builder.ipv4(*address, *prefix, None);
                primary = true;
            }
            IpAddr::V4(address) => extra.push((IpAddr::V4(*address), *prefix)),
            IpAddr::V6(address) => extra.push((IpAddr::V6(*address), *prefix)),
        }
    }
    #[cfg(target_os = "linux")]
    let builder = builder.offload(offload).multi_queue(multi);
    #[cfg(target_os = "macos")]
    let builder = if spec.tap() {
        let mut builder = builder.layer(tun_rs::Layer::L2).reuse_dev(false);
        if let Some(peer) = spec.peer() {
            builder = builder.peer_feth(peer.to_owned());
        }
        builder
    } else {
        builder
    };
    #[cfg(target_os = "windows")]
    let builder = {
        // A bare `wintun.dll` resolves through the Windows search path; an elevated process must load only the copy beside it.
        let dir = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
            .ok_or_else(|| io::Error::other("cannot locate the application directory"))?;
        let dll = dir.join("wintun.dll");
        if !dll.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "wintun.dll is missing beside the application: {}",
                    dll.display()
                ),
            ));
        }
        builder.wintun_file(dll.to_string_lossy().into_owned())
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let builder = builder;
    let device = builder.build_sync()?;
    #[cfg(target_os = "macos")]
    if spec.tap() {
        // The feth peer carries the I/O half and stays down until the host brings it up; `peer: "feth"` may allocate a free `fethN`, so the created device names the peer it actually paired with.
        let peer = feth_peer(&device.name().unwrap_or_default())?;
        if !std::process::Command::new("/sbin/ifconfig")
            .args([&peer, "up"])
            .status()
            .is_ok_and(|status| status.success())
        {
            return Err(io::Error::other(format!(
                "could not bring the TAP peer {peer} up"
            )));
        }
    }
    attach_addresses(&device, &extra);
    #[cfg(target_os = "linux")]
    let offload = device.tcp_gso();
    #[cfg(not(target_os = "linux"))]
    let _ = (multi, offload);
    Ok((device, offload, multi))
}

/// A mobile host already owns the device its VpnService or utun opened, so the userspace stack adopts that descriptor instead of opening one by name.
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
))]
pub(crate) fn build(
    spec: &Spec,
    _multi: bool,
    _offload: bool,
) -> io::Result<(SyncDevice, bool, bool)> {
    spec.validate()?;
    let fd = spec.fd().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the userspace stack needs the host's `fd` on this platform",
        )
    })?;
    // SAFETY: `dup` reads a live descriptor and returns a fresh one this process owns.
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::fcntl(duplicated, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: the duplicate is an owned TUN descriptor and closes with the device.
    let device = unsafe { SyncDevice::from_fd(duplicated)? };
    Ok((device, false, false))
}

/// Attach the addresses the builder's single IPv4 slot cannot carry: the device is already up with its primary address, so a platform that refuses one says so in a line rather than taking the inbound down.
fn attach_addresses(device: &SyncDevice, extra: &[(IpAddr, u8)]) {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        for (address, prefix) in extra {
            let attached = match address {
                IpAddr::V4(address) => device.add_address_v4(*address, *prefix).is_ok(),
                IpAddr::V6(address) => device.add_address_v6(*address, *prefix).is_ok(),
            };
            if !attached {
                eprintln!("tun inbound: the device refused the address {address}/{prefix}");
            }
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        let _ = device;
        if !extra.is_empty() {
            eprintln!(
                "tun inbound: this platform carries one IPv4 address; {} more left off the device",
                extra.len()
            );
        }
    }
}

/// The kernel offers UDP segment offload with the TCP offloads, but this handler dispatches one datagram per read and does not split an aggregate, so the device is narrowed back to the TCP mask the reference takes.
#[cfg(target_os = "linux")]
pub(crate) fn tcp_only_offload(device: &SyncDevice) -> bool {
    use std::os::fd::AsRawFd as _;
    let mask = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
    // SAFETY: the descriptor is a live TUN the device owns, and `TUNSETOFFLOAD` takes the mask by value.
    unsafe { libc::ioctl(device.as_raw_fd(), libc::TUNSETOFFLOAD, mask.cast_signed()) == 0 }
}

#[allow(clippy::needless_pass_by_value)]
fn spawn_queue(
    device: Arc<SyncDevice>,
    spec: &Spec,
    offload: bool,
    out: Outbound,
    stopping: Option<Arc<AtomicBool>>,
) -> Vec<thread::JoinHandle<()>> {
    #[cfg(target_os = "linux")]
    let headroom = VIRTIO_NET_HDR_LEN;
    #[cfg(not(target_os = "linux"))]
    let headroom = 0;
    let (packets, incoming) = mpsc::sync_channel(RX_QUEUE);
    let (outgoing, writes) = mpsc::sync_channel(TX_QUEUE);
    let (recycle, reused) = mpsc::sync_channel(RX_QUEUE);
    #[cfg(unix)]
    let (wake_read, wake_write) = std::os::unix::net::UnixStream::pair().expect("tun wake pair");
    #[cfg(unix)]
    let _ = wake_write.set_nonblocking(true);
    #[cfg(not(unix))]
    let wake_write = ();
    let config = device_config(spec);
    let dns_hijack = spec.dns_hijack();
    let stack_out = out.clone();
    let failed = Arc::new(AtomicBool::new(false));
    let stack_failed = Arc::clone(&failed);
    let stack_stopping = stopping.clone();
    let stack = thread::spawn(move || {
        #[cfg(unix)]
        crate::wg_stack::serve_tun_device(
            config,
            incoming,
            outgoing,
            stack_out,
            Some(recycle),
            headroom,
            dns_hijack,
            wake_read,
            stack_failed,
        );
        #[cfg(not(unix))]
        crate::wg_stack::serve_tun_device(
            config,
            incoming,
            outgoing,
            stack_out,
            Some(recycle),
            headroom,
            dns_hijack,
            stack_failed,
        );
        if let Some(flag) = &stack_stopping {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });
    let send_device = Arc::clone(&device);
    let send_stopping = stopping.clone();
    let recv_failed = Arc::clone(&failed);
    let send = thread::spawn(move || {
        send_loop(
            send_device,
            writes,
            offload,
            headroom,
            &failed,
            send_stopping.as_deref(),
        );
        if failed.load(std::sync::atomic::Ordering::Relaxed)
            && let Some(flag) = &send_stopping
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });
    let mtu = spec.mtu();
    let recv_stopping = stopping.clone();
    let recv = thread::spawn(move || {
        recv_loop(
            device,
            packets,
            reused,
            mtu,
            headroom,
            wake_write,
            stopping,
            None,
            &recv_failed,
        );
        if recv_failed.load(std::sync::atomic::Ordering::Relaxed)
            && let Some(flag) = &recv_stopping
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });
    vec![stack, send, recv]
}

pub(crate) fn device_config(spec: &Spec) -> DeviceConfig {
    DeviceConfig {
        secret: [0; 32],
        addresses: spec
            .addresses()
            .iter()
            .map(|(address, _)| *address)
            .collect(),
        peers: Vec::new(),
        mtu: spec.mtu(),
        reserved: [0; 3],
        is_client: Some(false),
        no_kernel_tun: true,
        large_segments: true,
        dns: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn take_slot(
    bufs: &mut [Vec<u8>],
    index: usize,
    end: usize,
    reuse: &Receiver<Vec<u8>>,
    mtu: usize,
) -> Vec<u8> {
    let mut replacement = reuse.try_recv().unwrap_or_default();
    replacement.clear();
    replacement.resize(VIRTIO_NET_HDR_LEN + mtu, 0);
    let mut bytes = std::mem::replace(&mut bufs[index], replacement);
    bytes.truncate(end);
    bytes
}

/// Queue one packet for the writer without parking the reader on a full ring: a removable inbound
/// still sees its stop flag under backpressure and lets the writer's `recv` unblock when it drops.
fn send_packet(
    packets: &SyncSender<Packet>,
    mut packet: Packet,
    stopping: Option<&AtomicBool>,
) -> bool {
    if stopping.is_none() {
        return packets.send(packet).is_ok();
    }
    loop {
        match packets.try_send(packet) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                if stopping.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                    return false;
                }
                packet = returned;
                thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub(crate) fn recv_loop(
    device: Arc<SyncDevice>,
    packets: SyncSender<Packet>,
    reuse: Receiver<Vec<u8>>,
    mtu: usize,
    headroom: usize,
    wake: WakeWriter,
    stopping: Option<Arc<AtomicBool>>,
    started: Option<SyncSender<()>>,
    failed: &AtomicBool,
) {
    let mut started = started;
    let mut original = vec![0u8; VIRTIO_NET_HDR_LEN + 65_535];
    let mut bufs: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE)
        .map(|_| vec![0u8; VIRTIO_NET_HDR_LEN + mtu])
        .collect();
    let mut sizes = vec![0usize; IDEAL_BATCH_SIZE];
    loop {
        if stopping
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return;
        }
        if let Some(started) = started.take() {
            let _ = started.send(());
        }
        let count =
            match device.recv_multiple(&mut original, &mut bufs, &mut sizes, VIRTIO_NET_HDR_LEN) {
                Ok(0) => {
                    if stopping.is_some() {
                        let _ = wait_readable(&device, std::time::Duration::from_millis(200));
                    }
                    continue;
                }
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let _ = wait_readable(&device, std::time::Duration::from_millis(200));
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    eprintln!("tun read: {error}");
                    failed.store(true, Ordering::Relaxed);
                    return;
                }
            };
        for index in 0..count {
            let end = VIRTIO_NET_HDR_LEN.saturating_add(sizes[index]);
            if sizes[index] == 0 || end > bufs[index].len() {
                continue;
            }
            let bytes = if headroom == VIRTIO_NET_HDR_LEN {
                take_slot(&mut bufs, index, end, &reuse, mtu)
            } else {
                packet_bytes(&reuse, &bufs[index][VIRTIO_NET_HDR_LEN..end])
            };
            let packet = Packet {
                peer: [0; 32],
                bytes,
                at: headroom,
            };
            if !send_packet(&packets, packet, stopping.as_deref()) {
                return;
            }
        }
        if count > 0 {
            wake_signal(&wake);
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub(crate) fn recv_loop(
    device: Arc<SyncDevice>,
    packets: SyncSender<Packet>,
    reuse: Receiver<Vec<u8>>,
    mtu: usize,
    _headroom: usize,
    wake: WakeWriter,
    stopping: Option<Arc<AtomicBool>>,
    started: Option<SyncSender<()>>,
    failed: &AtomicBool,
) {
    let mut buffer = vec![0u8; mtu.max(1500) + 64];
    #[cfg(windows)]
    let _ = started;
    #[cfg(not(windows))]
    let mut started = started;
    loop {
        if stopping
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return;
        }
        let size = {
            #[cfg(windows)]
            {
                if stopping.is_some() {
                    match device.try_recv(&mut buffer) {
                        Ok(0) => {
                            thread::sleep(std::time::Duration::from_millis(1));
                            continue;
                        }
                        Ok(size) => size,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(std::time::Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => {
                            eprintln!("tun read: {error}");
                            failed.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                } else {
                    match device.recv(&mut buffer) {
                        Ok(0) => continue,
                        Ok(size) if size <= buffer.len() => size,
                        Ok(_) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(std::time::Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => {
                            eprintln!("tun read: {error}");
                            return;
                        }
                    }
                }
            }
            #[cfg(not(windows))]
            {
                if stopping.is_some() {
                    if let Some(started) = started.take() {
                        let _ = started.send(());
                    }
                    match wait_readable(&device, std::time::Duration::from_millis(200)) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(error) => {
                            eprintln!("tun read: {error}");
                            failed.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
                match device.recv(&mut buffer) {
                    Ok(0) => continue,
                    Ok(size) if size <= buffer.len() => size,
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if wait_readable(&device, std::time::Duration::from_millis(200)).is_err() {
                            return;
                        }
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        eprintln!("tun read: {error}");
                        failed.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        };
        let bytes = packet_bytes(&reuse, &buffer[..size]);
        let packet = Packet {
            peer: [0; 32],
            bytes,
            at: 0,
        };
        if !send_packet(&packets, packet, stopping.as_deref()) {
            return;
        }
        wake_signal(&wake);
    }
}

#[cfg(target_os = "linux")]
fn send_loop(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    offload: bool,
    headroom: usize,
    failed: &AtomicBool,
    stopping: Option<&AtomicBool>,
) {
    if !offload {
        send_packets_offset(device, packets, failed, headroom, stopping);
        return;
    }
    let mut gro = GROTable::default();
    let mut pool: Vec<Vec<u8>> = (0..WRITE_BATCH)
        .map(|_| Vec::with_capacity(headroom + 65_535))
        .collect();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(WRITE_BATCH);
    loop {
        let Ok(packet) = packets.recv() else {
            return;
        };
        batch.clear();
        let mut take = |packet: &[u8], batch: &mut Vec<Vec<u8>>| {
            let mut buffer = pool
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(headroom + 65_535));
            buffer.clear();
            buffer.resize(headroom, 0);
            buffer.extend_from_slice(&packet[headroom..]);
            batch.push(buffer);
        };
        take(&packet, &mut batch);
        while batch.len() < WRITE_BATCH {
            match packets.try_recv() {
                Ok(packet) => take(&packet, &mut batch),
                Err(_) => break,
            }
        }
        match device.send_multiple(&mut gro, &mut batch, headroom) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if failed.load(Ordering::Relaxed)
                    || stopping.is_some_and(|stop| stop.load(Ordering::Relaxed))
                {
                    return;
                }
            }
            Err(error) if refused(&error) => {}
            Err(error) => {
                eprintln!("tun write: {error}");
                failed.store(true, Ordering::Relaxed);
                return;
            }
        }
        for mut buffer in batch.drain(..) {
            buffer.clear();
            pool.push(buffer);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn send_loop(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    _offload: bool,
    _headroom: usize,
    failed: &AtomicBool,
    stopping: Option<&AtomicBool>,
) {
    send_plain(device, packets, failed, None, stopping);
}

#[cfg(unix)]
pub(crate) fn wake_signal(wake: &WakeWriter) {
    let _ = unsafe { libc::write(wake.as_raw_fd(), c"".as_ptr().cast(), 1) };
}

#[cfg(not(unix))]
pub(crate) fn wake_signal(_: &WakeWriter) {}

#[cfg(target_os = "linux")]
#[allow(clippy::needless_pass_by_value)]
fn send_packets_offset(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    failed: &AtomicBool,
    offset: usize,
    stopping: Option<&AtomicBool>,
) {
    send_packets(&packets, failed, stopping, None, |packet| {
        let body = packet
            .get(offset..)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        device.send(body).map(|_| ())
    });
}

fn packet_bytes(reuse: &Receiver<Vec<u8>>, source: &[u8]) -> Vec<u8> {
    let mut bytes = reuse.try_recv().unwrap_or_default();
    bytes.clear();
    bytes.extend_from_slice(source);
    bytes
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn send_plain(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    failed: &AtomicBool,
    recycle: Option<SyncSender<Vec<u8>>>,
    stopping: Option<&AtomicBool>,
) {
    send_packets(&packets, failed, stopping, recycle.as_ref(), |packet| {
        write_device(&device, packet, stopping)
    });
}

/// A stoppable writer never parks in the device: Wintun's nonblocking send lets the reader see
/// `WouldBlock` and retry, while the safe path is the blocking send the tree always used.
#[cfg(windows)]
fn write_device(
    device: &SyncDevice,
    packet: &[u8],
    stopping: Option<&AtomicBool>,
) -> io::Result<()> {
    if stopping.is_some() {
        device.try_send(packet).map(|_| ())
    } else {
        device.send(packet).map(|_| ())
    }
}

#[cfg(not(windows))]
fn write_device(
    device: &SyncDevice,
    packet: &[u8],
    _stopping: Option<&AtomicBool>,
) -> io::Result<()> {
    device.send(packet).map(|_| ())
}

/// One packet the kernel refuses is the packet that is lost, not the device: `EINVAL` and
/// `EMSGSIZE` mean this send was bad, while every other error means the descriptor is gone.
#[cfg(unix)]
const REFUSED_WRITES: [i32; 2] = [libc::EINVAL, libc::EMSGSIZE];
#[cfg(windows)]
const REFUSED_WRITES: [i32; 2] = [10022, 10040];
#[cfg(not(any(unix, windows)))]
const REFUSED_WRITES: [i32; 0] = [];

pub(crate) fn refused(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::WouldBlock
    ) || error
        .raw_os_error()
        .is_some_and(|code| REFUSED_WRITES.contains(&code))
}

fn send_packets<W>(
    packets: &Receiver<Vec<u8>>,
    failed: &AtomicBool,
    stopping: Option<&AtomicBool>,
    recycle: Option<&SyncSender<Vec<u8>>>,
    mut write: W,
) where
    W: FnMut(&[u8]) -> io::Result<()>,
{
    while let Ok(packet) = packets.recv() {
        let waiting = std::time::Instant::now();
        let written = loop {
            match write(&packet) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && stopping.is_some() => {
                    if stopping.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                        return;
                    }
                    if waiting.elapsed() >= std::time::Duration::from_secs(5) {
                        break Ok(());
                    }
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                other => break other,
            }
        };
        if let Some(recycle) = recycle {
            let _ = recycle.try_send(packet);
        }
        if let Err(error) = written {
            if error.kind() == io::ErrorKind::WouldBlock || refused(&error) {
                continue;
            }
            eprintln!("tun write: {error}");
            failed.store(true, Ordering::Relaxed);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const REFUSED: i32 = libc::EINVAL;
    #[cfg(windows)]
    const REFUSED: i32 = 10022;
    #[cfg(unix)]
    const DEAD: i32 = libc::EBADF;
    #[cfg(windows)]
    const DEAD: i32 = 10009;

    #[test]
    #[cfg(any(unix, windows))]
    fn a_refused_packet_is_dropped_and_the_next_still_goes_out() {
        let (tx, rx) = mpsc::channel();
        tx.send(b"first".to_vec()).expect("queues");
        tx.send(b"second".to_vec()).expect("queues");
        drop(tx);
        let failed = AtomicBool::new(false);
        let mut seen = Vec::new();
        let mut first = true;
        let mut writes = 0;
        send_packets(&rx, &failed, None, None, |packet| {
            writes += 1;
            if first {
                first = false;
                return Err(io::Error::from_raw_os_error(REFUSED));
            }
            seen.push(packet.to_vec());
            Ok(())
        });
        assert_eq!(writes, 2, "the loop kept writing after the refusal");
        assert_eq!(seen, vec![b"second".to_vec()]);
        assert!(!failed.load(Ordering::Relaxed), "a refusal is not fatal");
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn a_dead_descriptor_still_stops_the_send_loop() {
        let (tx, rx) = mpsc::channel();
        tx.send(b"first".to_vec()).expect("queues");
        tx.send(b"second".to_vec()).expect("queues");
        drop(tx);
        let failed = AtomicBool::new(false);
        let mut writes = 0;
        send_packets(&rx, &failed, None, None, |_| {
            writes += 1;
            Err(io::Error::from_raw_os_error(DEAD))
        });
        assert_eq!(writes, 1, "a dead descriptor stops before the next packet");
        assert!(failed.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "macos")]
    fn removable_recv_preserves(nonblocking: bool) {
        let mut fds = [0; 2];
        // SAFETY: `socketpair` writes two live descriptors into the array.
        let paired =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(paired, 0, "open a fixture socket pair");
        let host = fds[0];
        // SAFETY: `dup` reads a live descriptor and returns a fresh one; both share their flags.
        let device_fd = unsafe { libc::dup(host) };
        assert!(device_fd >= 0, "duplicate the fixture descriptor");
        if nonblocking {
            let flags = unsafe { libc::fcntl(host, libc::F_GETFL) };
            assert!(flags >= 0, "read the fixture flags");
            assert_eq!(
                unsafe { libc::fcntl(host, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0,
                "make the fixture nonblocking"
            );
        }
        let before = unsafe { libc::fcntl(host, libc::F_GETFL) };
        // SAFETY: the duplicate is a live descriptor this test hands to the device.
        let device = unsafe { SyncDevice::from_fd(device_fd) }.expect("wrap the fixture");
        let stopping = Arc::new(AtomicBool::new(false));
        let (packets, _packets_rx) = mpsc::sync_channel(1);
        let (_reuse, reuse) = mpsc::sync_channel(1);
        let (wake, _wake_peer) = std::os::unix::net::UnixStream::pair().expect("wake pair");
        let (done, finished) = mpsc::sync_channel(0);
        let stop = Arc::clone(&stopping);
        let failed = AtomicBool::new(false);
        let (started, waiting) = mpsc::sync_channel(0);
        let reader = std::thread::spawn(move || {
            recv_loop(
                Arc::new(device),
                packets,
                reuse,
                1500,
                0,
                wake,
                Some(stop),
                Some(started),
                &failed,
            );
            let _ = done.send(());
        });
        waiting
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the reader reached its idle wait");
        stopping.store(true, Ordering::Relaxed);
        let timed_out = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err();
        if timed_out {
            // SAFETY: `fds[1]` is the live peer of the device's socket pair, so one datagram wakes the blocked receive.
            let _ = unsafe { libc::send(fds[1], [0u8].as_ptr().cast(), 1, 0) };
            let _ = finished.recv_timeout(std::time::Duration::from_secs(5));
        }
        reader.join().expect("the idle receiver ends");
        assert!(!timed_out, "the idle receiver did not stop");
        let after = unsafe { libc::fcntl(host, libc::F_GETFL) };
        assert_eq!(
            after & libc::O_NONBLOCK,
            before & libc::O_NONBLOCK,
            "the userspace receiver left the adopted descriptor's blocking mode unchanged"
        );
        unsafe { libc::close(host) };
        unsafe { libc::close(fds[1]) };
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_removable_userspace_receiver_leaves_a_blocking_descriptor_blocking() {
        removable_recv_preserves(false);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_removable_userspace_receiver_leaves_a_nonblocking_descriptor_nonblocking() {
        removable_recv_preserves(true);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_received_slot_keeps_its_allocation() {
        let (_reuse, reused) = mpsc::sync_channel(1);
        let mut bufs = vec![vec![0u8; VIRTIO_NET_HDR_LEN + 1500]];
        let base = bufs[0].as_ptr();
        let capacity = bufs[0].capacity();
        let end = VIRTIO_NET_HDR_LEN + 60;
        let bytes = take_slot(&mut bufs, 0, end, &reused, 1500);
        assert_eq!(bytes.as_ptr(), base, "the slot moved between buffers");
        assert_eq!(bytes.capacity(), capacity, "the slot reallocated");
        assert_eq!(bytes.len(), end);
        assert_ne!(bufs[0].as_ptr(), base, "the batch reused the returned slot");
        assert_eq!(bufs[0].len(), VIRTIO_NET_HDR_LEN + 1500);
    }
}
