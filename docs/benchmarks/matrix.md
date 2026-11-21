# Benchmark matrix

Every cell measures one client engine against a fixed server engine on loopback. The grid runs `ferrox` and `xray-core` as servers for every scenario they admit, and `sing-box` as a third server in the standalone Hysteria v1 cell, where `xray-core` reads v2 only, in the AnyTLS and TUIC cells, which `xray-core` does not carry at its pin, in the VLESS-over-QUIC cells, where `xray-core` has no QUIC transport, and in the WireGuard cells, whose pinned endpoint carries both roles. Every client the scenario's protocol and carrier admit is measured: `ferrox`, `xray-core`, `xray-core-rust`, `zeronet`, `sing-box`, and in the standard and full tiers `xray-rust` and `leaf`. `xray-core` is the reference wherever it participates; the standalone Hysteria v1, AnyTLS and TUIC cells have no `xray-core` control and are left to their ratio rows. AnyTLS and TUIC run `ferrox`, `sing-box`, `xray-core-rust` and `zeronet` as clients against both servers; the other engines name the missing protocol in the skipped list. `sing-box` is absent as a client from the `xhttp`, `kcp`, `quic`, Mux.Cool and `vless-hysteria` cells, the `vless-encryption-*` arms, and Shadowsocks cells with a transport: its pinned dialect has no such transport, no Mux.Cool carrier, and its VLESS has no `encryption` field. Those cells are skipped, not failed, and the raw Shadowsocks cells keep it. As a server it serves every scenario except the `xhttp` and `kcp` carriers, Mux.Cool, VLESS over `hysteria`, and the `vless-encryption-*` arms; among the QUIC cells it serves VLESS, AnyTLS and TUIC only, because its pinned server carries no VMess or Trojan inbound. Each remaining sing-box cell reads the same client outbound translated by `scripts/xray-to-singbox.py`; the Hysteria v1 cell translates both the standalone client and the server, which sing-box carries at its pin. At its pin sing-box strips the X25519MLKEM768 key share from a REALITY handshake, which xray-core's REALITY server requires, so `scripts/patch-sing-box.py` restores it before the build and the cell measures the transport rather than a TLS refusal. The nightly standard run also builds and runs sing-box, so the translated client is exercised without a full dispatch.

`zeronet` reads Mux.Cool on VLESS only, so the VMess, Trojan and Shadowsocks mux cells skip it. `leaf` joins where its pin has the protocol and carrier: VMess, Trojan, legacy Shadowsocks, and VLESS only with the Vision flow on raw TCP. It has no plain VLESS, `xhttp`, KCP, gRPC, HTTPUpgrade, Hysteria, VLESS encryption, or Shadowsocks 2022, and those cells name that in the bundle's skipped list. `scripts/xray-to-leaf.py` writes its TLS, REALITY and WebSocket layers as chain actors. `xray-rust` joins every standard and full cell its pin admits, except VLESS over Hysteria: its Hysteria outbound speaks Hysteria's own proxy protocol, not a transport that carries VLESS. `matrix_rust_client_config` removes the CA file and verify certificate it rejects while keeping the certificate pin.

Each scenario that has both servers also runs the reference client against both, so `scripts/check-matrix-legs.py` can say which leg lost: a ferrox client below the xray-core client on the xray-core server is a client hole, and a ferrox server below the xray-core server under the xray-core client is a server hole. The standalone Hysteria v1, AnyTLS and TUIC cells and the QUIC cells have no xray-core server control — xray-core reads only v2 Hysteria, carries neither AnyTLS nor TUIC, and has no QUIC transport at its pin — so that check leaves them to their ratio rows; the VMess and Trojan QUIC cells run the ferrox server only, because the pinned `sing-box` server carries neither protocol. The workload moves 128 MiB per flow, scaled down from the bytes a profile needs so a standard run finishes in minutes rather than hours. The smaller flow gives setup a larger share of each cell, so throughput, CPU and syscall ratios are read in their own cell rather than assumed unchanged from a longer run.

The tables are generated from `matrix-results.json` and the charts from the same cell bundles by `scripts/render-benchmark-charts.py`; CI commits the dated results and the latest charts here and opens a review PR. Do not edit between the markers by hand: a refresh replaces one runner block at a time.

Each bundle carries one image per test, with every server for that test side by side; it never merges two tests. The panel shows throughput, CPU per GiB, peak RSS, peak threads, cold start, kernel asks per MiB, the throughput repeats and their spread, from the same cells, so a reader never matches one test's bar against another test's. The spread panel names a `split` when one repeat separated from the others, which is what a median alone hides. The coverage grid is a markdown table, so a missing cell and its reason survive both text review and the artifact browser. The README block and the bundle's `README.md` are generated from the same `matrix-results.json`; `distribution.csv` carries the repeat spread in tidy form beside `table.csv`. A scheduled refresh compares the new medians with the last published run and leaves the committed markdown and charts alone when no cell moved by more than 10%, the top of the shared runner's noise band.

## Known holes (2026-10-25, rechecked 2026-11-05, standard / ubuntu-latest)

These are the gaps this tree still measures. `scripts/check-matrix-legs.py` reads the same list from `scripts/leg-gaps.txt`: a filed gap warns with its issue, while a new leg or one worse than its filed ratio by more than 0.10 fails the matrix. Remove a line only when a run proves the leg fixed, so the fix is a visible gate rather than a quiet baseline; a closed issue can still cover an open regression. `--gaps` (the workflow's `gaps` input) re-measures exactly the cells this file names, so a bug-fix slice checks whether any filed hole closed without paying for the whole grid; the refresh job never publishes that run. The 2026-10-27 recheck of the vmess, hysteria and gRPC rows is runs [40523513428](https://github.com/FerroxCo/ferrox/actions/runs/40523513428) and [40527294332](https://github.com/FerroxCo/ferrox/actions/runs/40527294332). The 2026-11-05 recheck of the two gRPC server legs is runs [41773748811](https://github.com/vpnguyishere/ferrox-plus/actions/runs/41773748811) (main, 0.99x and 1.07x) and [42095811948](https://github.com/vpnguyishere/ferrox-plus/actions/runs/42095811948) (five repeats, 1.05x and 1.11x): the ferrox server matches or beats the xray-core server with the xray-core client, so both rows are removed.

| leg | cell | measurement | issue |
| --- | ---- | ----------- | ----- |
| both | `vless-hysteria-down-8`, `vless-hysteria-up-1`, `vless-hysteria-duplex-8` | down server 32.8 vs 109.6 MiB/s and 1.82x CPU; upload/duplex below the gate | [#670](https://github.com/FerroxCo/ferrox/issues/670) |
| both | `vless-reality-xhttp-down-8` | all engines 0 B on the ferrox server; ferrox client 0 B on xray-core | [#668](https://github.com/FerroxCo/ferrox/issues/668) |

The coverage holes with no number — a client that cannot use a ferrox server at all — are tracked in [#480](https://github.com/FerroxCo/ferrox/issues/480): `shadowsocks2022-raw-down-8--srv-ferrox` drops xray-core-rust and zeronet, and xray-core-rust reads 0 in hysteria and reality-grpc on both servers. The remaining gaps — additional UDP cells, flows beyond 64 and carriers without a cell — stay in #384, #387 and #388 rather than being inferred from these rows. `sing-box` is absent as a client from the `xhttp`, `kcp`, `quic`, Mux.Cool and `vless-hysteria` cells and the three `vless-encryption-*` scenarios because its pinned dialect has no such transport, no Mux.Cool carrier, and no VLESS `encryption` field. It also carries no stream layer on a Shadowsocks outbound, so the Shadowsocks and Shadowsocks 2022 cells with a transport are skipped rather than failed; the raw cells keep it. The MASQUE `h1` and `h2c` cells run the ferrox server only: xray-core's MASQUE inbound serves CONNECT-IP over h3/h2, and Aether dials only h3/h2. The `vless-xhttp-h2c` cell runs the ferrox server only, because xray-core's cleartext xhttp is HTTP/1.1, not h2c, on both roles.

The same-key WARP readings live in `.github/workflows/warp-parity.yml`, not in a server row. That workflow registers one device with each engine, runs both engines against the local WARP server and Cloudflare's MASQUE edge with the same identity in both provenance directions, and reports startup, SOCKS setup, transfer rate and RSS. Its nested local leg runs the same fixed key through the matrix for `gool`, `gool-classic` and `mim`. The WARP cells below stay local, ferrox-server rows; the workflow is the cross-engine live check. Cloudflare's MASQUE data plane needs UDP egress; the lane fails when either server moves no bytes.

## Every standard configuration

The standard tier measures these 239 configurations: one row per scenario and server. The standalone Hysteria v1 rows, the AnyTLS and TUIC rows, and the VLESS-over-QUIC rows run the ferrox and sing-box servers; the VMess and Trojan QUIC rows run the ferrox server only, because no pinned reference serves their QUIC inbound; the WireGuard rows run all three, and the WARP rows run the ferrox server only because no pinned reference serves a WARP inbound. The full tier adds the 16-flow cells (`vless-raw-down-16`, `vless-raw-duplex-16`, `vless-tls-raw-duplex-16`, `vless-ws-down-16`), the missing up/duplex lanes for every method that had only a down lane, plus `vmess-tls-raw`, the v1 up and duplex lanes, and the userspace and kernel WireGuard up and duplex lanes, the 64-flow lanes, the Mux.Cool up/duplex/udp lanes and QUIC up/duplex lanes, and every protocol by carrier in the full grid: 321 scenarios and 609 configurations. The full tier is dispatched manually on `ubuntu-latest`, `ubuntu-24.04-arm` and `macos-15`; `windows-latest` is available by `workflow_dispatch`, because 321 scenarios across four runners is more than one matrix job may hold. The nightly standard tier runs on `ubuntu-latest` only, because a ratio is read inside one cell and four runners were measuring the same ratio four times. The matrix never runs on a pull request.

| scenario | server | measured |
| --- | --- | --- |
| `anytls-tls-raw-down-8` | ferrox | yes |
| `anytls-tls-raw-down-8` | sing-box | yes |
| `anytls-tls-raw-duplex-8` | ferrox | yes |
| `anytls-tls-raw-duplex-8` | sing-box | yes |
| `anytls-tls-raw-up-1` | ferrox | yes |
| `anytls-tls-raw-up-1` | sing-box | yes |
| `http-raw-down-8` | ferrox | yes |
| `http-raw-down-8` | xray-core | yes |
| `hysteria-v1-down-8` | ferrox | yes |
| `hysteria-v1-down-8` | sing-box | yes |
| `masque-down-8` | ferrox | yes |
| `masque-down-8` | xray-core | yes |
| `masque-h1-down-8` | ferrox | yes |
| `masque-h2-down-8` | ferrox | yes |
| `masque-h2-down-8` | xray-core | yes |
| `masque-h2c-down-8` | ferrox | yes |
| `shadowsocks-grpc-down-8` | ferrox | yes |
| `shadowsocks-grpc-down-8` | xray-core | yes |
| `shadowsocks-httpupgrade-down-8` | ferrox | yes |
| `shadowsocks-httpupgrade-down-8` | xray-core | yes |
| `shadowsocks-kcp-down-8` | ferrox | yes |
| `shadowsocks-kcp-down-8` | xray-core | yes |
| `shadowsocks-raw-down-8` | ferrox | yes |
| `shadowsocks-raw-down-8` | xray-core | yes |
| `shadowsocks-raw-mux-down-8` | ferrox | yes |
| `shadowsocks-raw-mux-down-8` | xray-core | yes |
| `shadowsocks-tls-raw-down-8` | ferrox | yes |
| `shadowsocks-tls-raw-down-8` | xray-core | yes |
| `shadowsocks-ws-down-8` | ferrox | yes |
| `shadowsocks-ws-down-8` | xray-core | yes |
| `shadowsocks2022-httpupgrade-down-8` | ferrox | yes |
| `shadowsocks2022-httpupgrade-down-8` | xray-core | yes |
| `shadowsocks2022-kcp-down-8` | ferrox | yes |
| `shadowsocks2022-kcp-down-8` | xray-core | yes |
| `shadowsocks2022-raw-down-8` | ferrox | yes |
| `shadowsocks2022-raw-down-8` | xray-core | yes |
| `shadowsocks2022-raw-mux-down-8` | ferrox | yes |
| `shadowsocks2022-raw-mux-down-8` | xray-core | yes |
| `shadowsocks2022-tls-raw-down-8` | ferrox | yes |
| `shadowsocks2022-tls-raw-down-8` | xray-core | yes |
| `shadowsocks2022-ws-down-8` | ferrox | yes |
| `shadowsocks2022-ws-down-8` | xray-core | yes |
| `socks-raw-down-8` | ferrox | yes |
| `socks-raw-down-8` | xray-core | yes |
| `trojan-grpc-down-8` | ferrox | yes |
| `trojan-grpc-down-8` | xray-core | yes |
| `trojan-httpupgrade-down-8` | ferrox | yes |
| `trojan-httpupgrade-down-8` | xray-core | yes |
| `trojan-hysteria-down-8` | ferrox | yes |
| `trojan-hysteria-down-8` | xray-core | yes |
| `trojan-kcp-down-8` | ferrox | yes |
| `trojan-kcp-down-8` | xray-core | yes |
| `trojan-quic-down-8` | ferrox | yes |
| `trojan-raw-down-8` | ferrox | yes |
| `trojan-raw-down-8` | xray-core | yes |
| `trojan-raw-mux-down-8` | ferrox | yes |
| `trojan-raw-mux-down-8` | xray-core | yes |
| `trojan-reality-raw-down-8` | ferrox | yes |
| `trojan-reality-raw-down-8` | xray-core | yes |
| `trojan-tls-grpc-down-8` | ferrox | yes |
| `trojan-tls-grpc-down-8` | xray-core | yes |
| `trojan-tls-httpupgrade-down-8` | ferrox | yes |
| `trojan-tls-httpupgrade-down-8` | xray-core | yes |
| `trojan-tls-raw-down-8` | ferrox | yes |
| `trojan-tls-raw-down-8` | xray-core | yes |
| `trojan-tls-ws-down-8` | ferrox | yes |
| `trojan-tls-ws-down-8` | xray-core | yes |
| `trojan-tls-xhttp-h2-down-8` | ferrox | yes |
| `trojan-tls-xhttp-h2-down-8` | xray-core | yes |
| `trojan-tls-xhttp-h3-down-8` | ferrox | yes |
| `trojan-tls-xhttp-h3-down-8` | xray-core | yes |
| `tuic-raw-down-8` | ferrox | yes |
| `tuic-raw-down-8` | sing-box | yes |
| `tuic-raw-duplex-8` | ferrox | yes |
| `tuic-raw-duplex-8` | sing-box | yes |
| `tuic-raw-udp-8` | ferrox | yes |
| `tuic-raw-udp-8` | sing-box | yes |
| `tuic-raw-up-1` | ferrox | yes |
| `tuic-raw-up-1` | sing-box | yes |
| `vless-encryption-raw-down-8` | ferrox | yes |
| `vless-encryption-raw-down-8` | xray-core | yes |
| `vless-encryption-reality-raw-down-8` | ferrox | yes |
| `vless-encryption-reality-raw-down-8` | xray-core | yes |
| `vless-encryption-tls-raw-down-8` | ferrox | yes |
| `vless-encryption-tls-raw-down-8` | xray-core | yes |
| `vless-grpc-bulk-down-1` | ferrox | yes |
| `vless-grpc-bulk-down-1` | xray-core | yes |
| `vless-grpc-down-8` | ferrox | yes |
| `vless-grpc-down-8` | xray-core | yes |
| `vless-grpc-multi-down-8` | ferrox | yes |
| `vless-grpc-multi-down-8` | xray-core | yes |
| `vless-httpupgrade-down-8` | ferrox | yes |
| `vless-httpupgrade-down-8` | xray-core | yes |
| `vless-httpupgrade-ed-down-8` | ferrox | yes |
| `vless-httpupgrade-ed-down-8` | xray-core | yes |
| `vless-hysteria-down-8` | ferrox | yes |
| `vless-hysteria-down-8` | xray-core | yes |
| `vless-kcp-down-8` | ferrox | yes |
| `vless-kcp-down-8` | xray-core | yes |
| `vless-quic-down-8` | ferrox | yes |
| `vless-quic-down-8` | sing-box | yes |
| `vless-raw-down-1` | ferrox | yes |
| `vless-raw-down-1` | xray-core | yes |
| `vless-raw-down-8` | ferrox | yes |
| `vless-raw-down-8` | xray-core | yes |
| `vless-raw-duplex-8` | ferrox | yes |
| `vless-raw-duplex-8` | xray-core | yes |
| `vless-raw-idle` | ferrox | yes |
| `vless-raw-idle` | xray-core | yes |
| `vless-raw-idle-100` | ferrox | yes |
| `vless-raw-idle-100` | xray-core | yes |
| `vless-raw-idle-1000` | ferrox | yes |
| `vless-raw-idle-1000` | xray-core | yes |
| `vless-raw-mixed-8` | ferrox | yes |
| `vless-raw-mixed-8` | xray-core | yes |
| `vless-raw-mux-down-8` | ferrox | yes |
| `vless-raw-mux-down-8` | xray-core | yes |
| `vless-raw-mux-duplex-8` | ferrox | yes |
| `vless-raw-mux-duplex-8` | xray-core | yes |
| `vless-raw-mux-udp-8` | ferrox | yes |
| `vless-raw-mux-udp-8` | xray-core | yes |
| `vless-raw-mux-up-1` | ferrox | yes |
| `vless-raw-mux-up-1` | xray-core | yes |
| `vless-raw-reconnect-16` | ferrox | yes |
| `vless-raw-reconnect-16` | xray-core | yes |
| `vless-raw-routed-down-8` | ferrox | yes |
| `vless-raw-routed-down-8` | xray-core | yes |
| `vless-raw-setup-1k` | ferrox | yes |
| `vless-raw-setup-1k` | xray-core | yes |
| `vless-raw-tcp-latency-1` | ferrox | yes |
| `vless-raw-tcp-latency-1` | xray-core | yes |
| `vless-raw-udp-8` | ferrox | yes |
| `vless-raw-udp-8` | xray-core | yes |
| `vless-raw-up-1` | ferrox | yes |
| `vless-raw-up-1` | xray-core | yes |
| `vless-reality-grpc-down-8` | ferrox | yes |
| `vless-reality-grpc-down-8` | xray-core | yes |
| `vless-reality-raw-down-8` | ferrox | yes |
| `vless-reality-raw-down-8` | xray-core | yes |
| `vless-reality-xhttp-down-8` | ferrox | yes |
| `vless-reality-xhttp-down-8` | xray-core | yes |
| `vless-tls-grpc-down-8` | ferrox | yes |
| `vless-tls-grpc-down-8` | xray-core | yes |
| `vless-tls-grpc-multi-down-8` | ferrox | yes |
| `vless-tls-grpc-multi-down-8` | xray-core | yes |
| `vless-tls-httpupgrade-down-8` | ferrox | yes |
| `vless-tls-httpupgrade-down-8` | xray-core | yes |
| `vless-tls-httpupgrade-ed-down-8` | ferrox | yes |
| `vless-tls-httpupgrade-ed-down-8` | xray-core | yes |
| `vless-tls-raw-down-8` | ferrox | yes |
| `vless-tls-raw-down-8` | xray-core | yes |
| `vless-tls-raw-duplex-8` | ferrox | yes |
| `vless-tls-raw-duplex-8` | xray-core | yes |
| `vless-tls-raw-up-1` | ferrox | yes |
| `vless-tls-raw-up-1` | xray-core | yes |
| `vless-tls-ws-down-8` | ferrox | yes |
| `vless-tls-ws-down-8` | xray-core | yes |
| `vless-tls-ws-ed-down-8` | ferrox | yes |
| `vless-tls-ws-ed-down-8` | xray-core | yes |
| `vless-tls-xhttp-h1-down-8` | ferrox | yes |
| `vless-tls-xhttp-h1-down-8` | xray-core | yes |
| `vless-tls-xhttp-h2-down-8` | ferrox | yes |
| `vless-tls-xhttp-h2-down-8` | xray-core | yes |
| `vless-tls-xhttp-h2-streamone-mux-down-8` | ferrox | yes |
| `vless-tls-xhttp-h2-streamone-mux-down-8` | xray-core | yes |
| `vless-tls-xhttp-h3-down-8` | ferrox | yes |
| `vless-tls-xhttp-h3-down-8` | xray-core | yes |
| `vless-vision-reality-android-down-8` | ferrox | yes |
| `vless-vision-reality-android-down-8` | xray-core | yes |
| `vless-vision-reality-bulk-down-1` | ferrox | yes |
| `vless-vision-reality-bulk-down-1` | xray-core | yes |
| `vless-vision-reality-edge-down-8` | ferrox | yes |
| `vless-vision-reality-edge-down-8` | xray-core | yes |
| `vless-vision-reality-firefox-down-8` | ferrox | yes |
| `vless-vision-reality-firefox-down-8` | xray-core | yes |
| `vless-vision-reality-ios-down-8` | ferrox | yes |
| `vless-vision-reality-ios-down-8` | xray-core | yes |
| `vless-vision-reality-random-down-8` | ferrox | yes |
| `vless-vision-reality-random-down-8` | xray-core | yes |
| `vless-vision-reality-randomized-down-8` | ferrox | yes |
| `vless-vision-reality-randomized-down-8` | xray-core | yes |
| `vless-vision-reality-raw-down-8` | ferrox | yes |
| `vless-vision-reality-raw-down-8` | xray-core | yes |
| `vless-vision-reality-safari-down-8` | ferrox | yes |
| `vless-vision-reality-safari-down-8` | xray-core | yes |
| `vless-vision-reality-udp-8` | ferrox | yes |
| `vless-vision-reality-udp-8` | xray-core | yes |
| `vless-vision-tls-raw-down-8` | ferrox | yes |
| `vless-vision-tls-raw-down-8` | xray-core | yes |
| `vless-ws-down-8` | ferrox | yes |
| `vless-ws-down-8` | xray-core | yes |
| `vless-ws-ed-down-8` | ferrox | yes |
| `vless-ws-ed-down-8` | xray-core | yes |
| `vless-xhttp-down-8` | ferrox | yes |
| `vless-xhttp-down-8` | xray-core | yes |
| `vless-xhttp-h2c-down-8` | ferrox | yes |
| `vless-xhttp-packets-down-8` | ferrox | yes |
| `vless-xhttp-packets-down-8` | xray-core | yes |
| `vless-xhttp-streamone-down-8` | ferrox | yes |
| `vless-xhttp-streamone-down-8` | xray-core | yes |
| `vless-xhttp-streamup-down-8` | ferrox | yes |
| `vless-xhttp-streamup-down-8` | xray-core | yes |
| `vmess-grpc-down-8` | ferrox | yes |
| `vmess-grpc-down-8` | xray-core | yes |
| `vmess-httpupgrade-down-8` | ferrox | yes |
| `vmess-httpupgrade-down-8` | xray-core | yes |
| `vmess-kcp-down-8` | ferrox | yes |
| `vmess-kcp-down-8` | xray-core | yes |
| `vmess-quic-down-8` | ferrox | yes |
| `vmess-raw-down-8` | ferrox | yes |
| `vmess-raw-down-8` | xray-core | yes |
| `vmess-raw-mux-down-8` | ferrox | yes |
| `vmess-raw-mux-down-8` | xray-core | yes |
| `vmess-reality-raw-down-8` | ferrox | yes |
| `vmess-reality-raw-down-8` | xray-core | yes |
| `vmess-tls-grpc-down-8` | ferrox | yes |
| `vmess-tls-grpc-down-8` | xray-core | yes |
| `vmess-tls-httpupgrade-down-8` | ferrox | yes |
| `vmess-tls-httpupgrade-down-8` | xray-core | yes |
| `vmess-tls-raw-down-8` | ferrox | yes |
| `vmess-tls-raw-down-8` | xray-core | yes |
| `vmess-tls-ws-down-8` | ferrox | yes |
| `vmess-tls-ws-down-8` | xray-core | yes |
| `vmess-tls-xhttp-h2-down-8` | ferrox | yes |
| `vmess-tls-xhttp-h2-down-8` | xray-core | yes |
| `vmess-tls-xhttp-h3-down-8` | ferrox | yes |
| `vmess-tls-xhttp-h3-down-8` | xray-core | yes |
| `vmess-xhttp-down-8` | ferrox | yes |
| `vmess-xhttp-down-8` | xray-core | yes |
| `warp-gool-classic-down-8` | ferrox | yes |
| `warp-gool-down-8` | ferrox | yes |
| `warp-masque-down-8` | ferrox | yes |
| `warp-mim-down-8` | ferrox | yes |
| `wireguard-kernel-raw-down-8` | ferrox | yes |
| `wireguard-kernel-raw-down-8` | sing-box | yes |
| `wireguard-kernel-raw-down-8` | xray-core | yes |
| `wireguard-raw-down-8` | ferrox | yes |
| `wireguard-raw-down-8` | sing-box | yes |
| `wireguard-raw-down-8` | xray-core | yes |

## Not measured yet

These are the ways a config can name a method that no cell measures. A row here is a known gap in the harness, a feature this tree does not implement, or a peer-only protocol, not a claim that the method works.

| method | carrier or security | direction | status |
| --- | --- | --- | --- |
| vless | xhttp `xmux` on H1 or split modes | down, up | no cell; only a stream-one H2 session is pooled, and H1, packet-up and stream-up keep their own connection |
| any | TUN fake DNS, stale-flow eviction | down, request/response | no cell; the TUN device itself is measured by `tun-bench.yml` against hev and sing-tun, but nothing drives fake DNS through it or counts a quiet flow's eviction |
| sing-box | Hysteria2, Naive, ShadowTLS, Snell, SSH, OpenVPN, OpenConnect, Tor, Tailscale | down | no cell; sing-box-only protocols with no ferrox or xray-core client ([#603](https://github.com/Ferrocite/ferrox/issues/603), [#604](https://github.com/Ferrocite/ferrox/issues/604), P0 coverage issue) |
| any | UDP DNS through the SOCKS front | request/response | no cell; UDP echo is measured, resolver replies are not |
| any | IPv6 target | down | no cell |
| vless | uTLS fingerprints beyond chrome, firefox, safari, edge, ios, android, random and randomized | down | no cell |
| any | upstream servers, CDN fronts and the Psiphon network | down | no cell; these need the live network, so they run in the CI-only live lane |

<!-- benchmark-matrix:start -->
<!-- benchmark-matrix:end -->
