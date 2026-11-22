# Ferrox vs Xray-core feature map

Pinned reference: `upstream/xray-core` @ `c456141` (`upstream/pins.toml`). This tree: `crates/ferrox-core`, `crates/ferrox-app`, `docs/function/`.

What runs against what: `xray-rust` interop (24 tests, seam `XRAY_VLESS_FULL_BINARY`), `zeronet` `xray_oracle` (9 tests, seam `ZRAY_XRAY_BINARY`), and `xray-core`'s `testing/scenarios` built at run time and spawned with `-config=stdin: -format=pb` via `go -overlay` (`scripts/xray-scenarios.sh`), which `ferrox-app` reads in `crates/ferrox-app/src/xray_pb.rs`. At this pin the map answers 44 of 73, across http, socks, dokodemo, dns, feature, policy, shadowsocks (legacy AEAD and 2022), tls, vless, vmess, masque and wireguard; `conformance.yml` gates those 44, plus two `dialerProxy` tests and five commander tests (51 in all). All 73 run into the scenario map. `xray-core`'s own unit tests are in-process with no seam and stay in `xray-baseline.yml`.

## What ferrox has that xray-core does not

| area | ferrox | xray-core |
| --- | --- | --- |
| Foxy / FoxyVPN lane | `ferrox-core/src/foxy/` — FxA login + 2FA, Hawk-signed exchange, bot challenge, Guardian token, Remote Settings catalog, country pin, SPKI pins, split tunnel, upstream proxy chain, auto = QUIC → H2 → H1 | none (it is a separate product) |
| TUN as a tun2socks engine | roadmap goal 3; hev-socks5-tunnel is the default comparator | `proxy/tun` exists, on xray's own lightweight `netstack.go` (gVisor left the source at #7156), and it exposes no tun2socks-style policy split |
| Record layer, four widths, one source | `record.rs` + `Lanes` trait: portable/NEON/SSE2/AVX2 execute the same source | per-arch crypto with divergent implementations |
| Count-gated claims | exact ops/syscall/copy counts per method, `scripts/method-counts.txt` ⇔ pages | no equivalent gate |
| KCP bit-exact oracle | `kcp::oracle` vs pinned Go KCP | KCP implementation, no cross-implementation oracle in-tree |

## What xray-core has that ferrox does not

### Proxy protocols

| xray-core | ferrox state |
| --- | --- |
| Trojan share-link `trojan://` parser | implemented (`ferrox_core::trojan::TrojanLink`; `check`/`run` accept it beside `vless://`) |
| Dokodemo transparent inbound | done (row 27): tcp/udp rewrite, `portMap`, `followRedirect` over `SO_ORIGINAL_DST`/`DIOCNATLOOK` and Linux `TPROXY`, UDP ancillary original-destination replies on Linux, `finalmask.tcp` fragment chain, JSON and protobuf config including the protobuf `tproxy` mode and receiver marker; Windows, macOS UDP, the non-follow missing-rewrite fallback, and partial `portMap` spellings are named open |
| Freedom — `domainStrategy`, fragment, dialer fields | implemented (row 45): `domainStrategy`, `fragment`, `proxyProtocol`, `noises` and `finalRules` from JSON and xray protobuf; explicit rules only |
| DNS proxy + fakeDNS + hosts + DoH/DoQ/local nameservers (`app/dns`) | `proxy/dns` outbound done (row 29); the resolver app implemented (row 118): UDP/TCP/DoT/DoH/DoQ, cache, hosts, FakeDNS, filters and parallel groups |
| Blackhole outbound | done (row 28): the outbound shares the three answers and the 403's bytes the reference's own (an oracle drives the pinned handler and the comparison is octet for octet); the flow ends when the peer is done. The Ferrox inbound is an extension — `xray-core` registers `blackhole` only as an outbound — and gives each accepted flow the same answer, draining only when it answered. The datagram lane refuses the association with `0x07` ([blackhole](function/blackhole.md)) |
| Loopback | done (row 30) |
| WireGuard proxy (`proxy/wireguard`, lightweight `netstack.go`) | implemented (row 74): client outbound and server inbound over `smoltcp`, IPv4/IPv6 TCP and UDP, JSON and protobuf config, WARP, remoteDNS and kernel TUN; `TestWireguard` is the CI gate ([wireguard](function/wireguard.md)); AmneziaWG is row 75 |
| Hysteria v1 proxy (`proxy/hysteria`) | implemented (row 44): both roles, TCP and UDP, xplus and port hop |
| MASQUE proxy (`proxy/masque`) | implemented over h3/h2/h1/h2c, both roles (rows 21, 76, 77): `protocol: masque` inbound with an address pool, and the `masque` transport dial; a shared TLS port selects h3, h2 or h1 by ALPN, and cleartext h2c when `security: none` is explicit; the reference's flat `address`/`port` outbound and `users`/`clients` with `pass` read the same edge and table |
| TUN inbound (`proxy/tun`) | done (row 32) |
| uTLS fingerprints per connection | implemented, client (row 41): 50 names onto 31 pinned presets; psk and random families are not byte-gated |
| ECH | done, both roles and both transports: `echSockopt` is applied to the DNS query socket, TLS serves and accepts an offer, and QUIC both dials with the same list and serves it while a client that omits it still falls back; an accepted offer is unchanged, a rejected TLS offer is redialled once with the BoringSSL retry list where Go's `SendAsRetry=false` sends none — a deliberate superset, not an open gap — and a rejected QUIC dial fails without a retry (row 42) |
| VLESS stream encryption (`encryption` field, XOR/MLKEM) | implemented (row 37): both roles raw/TLS/REALITY and carried ws/gRPC/httpUpgrade/xhttp (H1/h2c)/http header, with Vision over carried; server UDP/mux/reverse and client UDP/mux served; xhttp over H2 is not carried |
| XTLS Vision UDP-over-443 flow | implemented, outbound only (row 38): strips to Vision and widens the UDP 443 gate |
| REALITY ML-DSA-65 binding (`mldsa65Seed` / `mldsa65Verify`) | partial (row 164; both fields are validated with the reference's lengths and messages, a seeded server signs the leaf's first extension with a deterministic ML-DSA-65 key over `HMAC-SHA512(auth_key, public \|\| ClientHello.Raw \|\| ServerHello.Raw)`, and a client with `mldsa65Verify` checks it; the ZeroNet oracle row `reality_with_the_mldsa65_binding_matches_the_oracle` is not wired yet) |

### Transports

| xray-core | ferrox state |
| --- | --- |
| TCP | done |
| WebSocket (`?ed=` both roles) | done |
| gRPC | done, own HTTP/2; the multi-mode dial (`multiMode`), the reference's method-path derivation and the TLS authority fallback are carried, and a custom service without a split serves both message shapes on its one path ([carrier-grpc](function/carrier-grpc.md)) |
| HTTPUpgrade | done, both roles, `?ed=N` carried (row 17) |
| xHTTP / SplitHTTP modes (packet-up, stream-up, stream-one, padding/placement) | all three modes both roles: the dial resolves an unstated `mode` and mints the session the hub validates, packets split at `uplinkChunkSize` into body or `X-Data-{i}`/cookie parts, posts paced by `scMinPostsIntervalMs`, and a relay half-close ends the request body ([carrier-xhttp](function/carrier-xhttp.md)) |
| KCP/mKCP + FinalMask (aes128gcm, header, original) | core done; finalmask `fragment` done (row 34), other mask types planned |
| Hysteria v2 transport (network `hysteria`, masquerade surface) | done as `vless-hysteria` / `protocol: hysteria` over quiche, both roles (row 20); datagrams, salamander obfs, masquerade site |
| MASQUE transport | CONNECT-IP client and terminating server over h3/h2/h1/h2c (rows 21, 76, 77); a shared TLS port selects h3, h2 or h1 by ALPN, and cleartext h2c when `security: none` is explicit |
| XDrive (remote-storage carrier) | implemented, both roles (row 35): four services, Drive `slotStore`/spares, XMUX limits and h3 `quicParams` |
| Browser dialer | implemented (row 50): WebSocket and packet-up xhttp for VLESS, VMess, Trojan and Shadowsocks |
| Tagged connections | done (row 125, [engine-tagged](function/engine-tagged.md)); observatory webhooks planned |
| UDP `transport/internet/udp` fullcone/NAT behavior | mux-cool carries XUDP; standalone UDP transport planned |
| Unix sockets | done (row 33) |

### Features / apps

| xray-core | ferrox state |
| --- | --- |
| DNS client: DoH, DoQ, local, cached, fakeDNS | `proxy/dns` outbound done (row 29); the resolver app implemented (row 118): UDP/TCP/DoT/DoH/DoQ, cache, hosts, FakeDNS, filters and parallel groups |
| Router with rules, balancers (leastload/leastping/random), webhook | rules, selectors, geodata refresh and the `webhook` action partial (row 115); the four balancer strategies done, urltest and selector planned (row 117); rule sets and scripts partial (row 116) |
| Observatory / burst probe | implemented (row 124): legacy and burst probes, `leastPing`/`leastLoad`, healthcheck front |
| Reverse portal / bridge | done (row 119): modern VLESS reverse both roles over the stream transports it carries (raw, TLS, REALITY, WebSocket, gRPC, HTTPUpgrade, HTTPHeader, xHTTP, QUIC, KCP, hysteria, xdrive; MASQUE, plain HTTP and unknown networks are refused); TCP bridge flows leave through any routed outbound; UDP flows through any routed outbound that serves UDP |
| Stats, metrics (Prometheus), policy manager | implemented (row 54): reference counters, an online map with source IPs and last-seen times, access log and policies |
| `app/commander` gRPC API (config/inbound/outbound/log/router/stats) | implemented (row 120): every service, including `AddRule`/`RemoveRule` over the live table; an add refuses a duplicate tag, an unknown target, or a rule a server inbound cannot evaluate |
| Geodata (.dat) loader/downloader | partial (row 115): geodata refresh carried inside routing; the full loader/downloader surface is not |
| OCSP, antireplay, time-window caches | implemented (row 49): OCSP fetch and staple on every lane, plus the VMess session-history cache |
| Freedom fragment, VLESS encryption fragment | freedom fragment done (row 45); VLESS encryption implemented (row 37) |
| Sniffer (HTTP/TLS/QUIC/bittorrent) + dispatcher sniffer | implemented (engine-sniffing: HTTP/TLS/QUIC/FakeDNS, bittorrent, UDP, plain-HTTP protocol, loopback outbound sniffing and the named inbound's second routing pass are carried) |
| Config schema for every protocol (`infra/conf`) | ferrox-app's own JSON dialect; the protobuf `xray.core.Config` covers the shapes the http, dokodemo, vmess, vless, shadowsocks, shadowsocks_2022 and loopback scenarios write (`xray_pb.rs`), every other field refused by number or name |
| finalmask: fragment, header/custom, noise, realm, salamander, sudoku, udphop, xdns, xicmp, xmc | `fragment`, `sudoku`, `header-custom` and `xmc` done (row 34), salamander on hysteria, mkcp-legacy on KCP; the rest planned (`obfs-finalmask`) |

## What to build next

Every planned or absent row above is a `README.md` matrix row the `crates/ferrox-prompt/prompts.md` templates draw their target from. `cargo run -p ferrox-prompt -- next` hands over the next outstanding row, ordered by leverage and nearness-to-done.
