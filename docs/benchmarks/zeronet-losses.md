# Where zeronet beat ferrox (matrix #46)

`zeronet` is being removed from the comparator set: its pinned rev
(`29e7a95e`) was force-pushed away upstream, so the fetch step cannot resolve it
and every matrix run fails before it builds anything. Before the pin went, one
full standard-tier run measured zeronet against ferrox across the whole grid.
This page keeps the cells where zeronet was faster, so the knowledge survives
the removal and a future slice can target them.

Source: benchmark-matrix run
[45941236575](https://github.com/ferroxdev/ferrox-2/actions/runs/45941236575)
(#46, `main` @ `84a286ad`), standard tier, `linux-x86_64`, ubuntu-latest,
4 vCPU (AMD EPYC 9V74), three repeats. Throughput is the median of the three
repeats in MiB/s; the ratio is `zeronet / ferrox` for the same cell (same
runner, same server), so a value above 1.00 means zeronet moved more bytes.

## Throughput: 12 cells where zeronet outran ferrox

| cell | server | ferrox | zeronet | zeronet/ferrox | xray-core | aether | sing-box |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `tuic-raw-duplex-8--srv-sing-box` | sing-box | 192.6 | 295.1 | **1.53×** | — | — | 219.3 |
| `tuic-raw-down-8--srv-sing-box` | sing-box | 302.5 | 441.8 | **1.46×** | — | — | 296.7 |
| `vless-raw-mux-duplex-8--srv-ferrox` | ferrox | 845.3 | 1227.7 | **1.45×** | 622.7 | — | — |
| `vless-raw-mux-up-1--srv-ferrox` | ferrox | 1131.5 | 1630.1 | **1.44×** | 1142.3 | — | — |
| `tuic-raw-duplex-8--srv-ferrox` | ferrox | 205.3 | 272.2 | **1.33×** | — | — | 206.4 |
| `tuic-raw-up-1--srv-sing-box` | sing-box | 226.0 | 290.0 | **1.28×** | — | — | 369.9 |
| `tuic-raw-down-8--srv-ferrox` | ferrox | 311.0 | 396.1 | **1.27×** | — | — | 287.8 |
| `vless-tls-ws-down-8--srv-xray-core` | xray-core | 531.1 | 587.6 | **1.11×** | 163.2 | — | 451.5 |
| `vless-raw-mux-duplex-8--srv-xray-core` | xray-core | 1142.3 | 1251.2 | **1.10×** | 697.4 | — | — |
| `trojan-tls-ws-down-8--srv-xray-core` | xray-core | 814.9 | 883.1 | **1.08×** | 431.6 | — | 641.7 |
| `vless-raw-up-1--srv-xray-core` | xray-core | 1677.6 | 1800.8 | **1.07×** | 1968.6 | — | 1394.4 |
| `vless-grpc-bulk-down-1--srv-xray-core` | xray-core | 517.9 | 552.6 | **1.07×** | 164.4 | — | 172.8 |

The losses cluster in two places: **TUIC** (raw down/up/duplex, 1.27–1.53×) and
**VLESS Mux.Cool** (`vless-raw-mux-*`, 1.10–1.45×). Those are the shapes to look
at first if the gap matters. The rest are single-digit-percent deficits on
xray-core-server WebSocket, raw-up and gRPC-bulk cells. In every row zeronet is
also well under the pinned xray-core client where both run, so the cells are not
xray-core's to win either.

## Targeted after #46

Run
[46141630494](https://github.com/ferroxdev/ferrox-2/actions/runs/46141630494)
(`tuic-duplex-win` @ `6377051d`) re-ran the worst TUIC cell at the full tier.
`tuic-raw-duplex-8--srv-sing-box` read ferrox **632.2 MiB/s** (three repeats
705.9 / 632.2 / 632.2), **3.28×** the #46 leg and **2.14×** zeronet's 295.1;
sing-box read 420.9 in the same cell against 219.3 in #46, so that runner's own
speed is part of the absolute ratio. The same-cell ratio moved **0.878 → 1.50**.
The change is the client lane's blocking connection lock, described in
`docs/function/tuic.md`. The cell's own gate is still red against
`xray-core-rust` (981.7), a comparator absent from #46.
`tuic-raw-up-1--srv-sing-box` read ferrox 430.6 against sing-box's 508.6
(0.847×), up from 0.593× on the prior branch run but still under the comparator.

## CPU per GiB: 10 cells where zeronet used less

Lower is better. zeronet's CPU/GiB is below ferrox's in ten cells (values are
`ms/GiB`):

| cell | server | ferrox | zeronet | zeronet/ferrox |
| --- | --- | ---: | ---: | ---: |
| `vless-tls-xhttp-h2-streamone-mux-down-8` | xray-core | 4000 | 1840 | 0.46× |
| `tuic-raw-duplex-8` | sing-box | 8240 | 4800 | 0.58× |
| `vless-grpc-bulk-down-1` | xray-core | 1840 | 1200 | 0.65× |
| `tuic-raw-down-8` | sing-box | 4160 | 3200 | 0.77× |
| `tuic-raw-duplex-8` | ferrox | 6560 | 5360 | 0.82× |
| `vless-httpupgrade-down-8` | xray-core | 480 | 400 | 0.83× |
| `vless-raw-mux-duplex-8` | ferrox | 1040 | 880 | 0.85× |
| `tuic-raw-down-8` | ferrox | 3680 | 3200 | 0.87× |
| `trojan-tls-xhttp-h2-down-8` | xray-core | 2320 | 2080 | 0.90× |
| `vless-grpc-bulk-down-1` | ferrox | 1200 | 1120 | 0.93× |

Again TUIC and Mux.Cool dominate; the TUIC CPU gap is where zeronet's throughput
win and its CPU win are the same effect.

## Peak RSS: zeronet is leaner almost everywhere

zeronet's peak resident set is below ferrox's in 128 of the measured cells,
typically 0.62–0.90× (for example ~12.5 MiB against ferrox's ~20 MiB on the
REALITY/ShadowSocks TLS download cells). This is memory, not speed, and is
recorded here only so the removal does not erase the fact; the ferrox RSS gap
against aether and xray-core is tracked separately by the RSS gate.

## What this means now

- zeronet is no longer fetched or measured, so these rows cannot re-open the
  gate. This page is the durable record.
- The `scripts/comparator-gaps.txt` lines that named zeronet were removed with
  the comparator; they are folded into the tables above.
- If any of these shapes become a priority, the TUIC lane and VLESS Mux.Cool
  relay are the two levers with the largest, most consistent zeronet margin.
