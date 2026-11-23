# Ferrox prompt library

Twenty-one reusable templates. `ferrox-prompt` fills each one from the live matrix in `README.md` and the pins in `upstream/pins.toml`, so `next` names the concrete row to work on rather than a hand-transcribed idea; `issue <number>` fills the one template that takes a regression issue. If the tool and these files disagree, the files are right — that is why `ferrox-prompt check` is a CI step and `tests/contract.rs` locks the properties below.

## Grammar

One `## P<n> · <title>` section per template, ids `1..=n` with no gaps. Required lines, `check` fails if one is missing:

| line | meaning |
| --- | --- |
| `**When to use:**` | the situation that calls for this slice |
| `**Status:**` | `todo`, `doing`, `done`, `blocked`; a template stays `todo` because it is a standing kind of work |
| `**Leverage:**` | 1-5, the advisor's ranking key |
| `**Effort:**` | `small`, `medium`, `large`; ties break to the smaller one |
| `**Gates:**` | semicolon-separated checks that must pass; wrap a command in backticks so it reads as one |
| `**Targets:**` | `open`, `implemented`, `all`, or `none` — which matrix rows the template draws from |

Optional: `**Depends on:**` (prompt ids), `**Touches:**` (paths; `+` prefix for one created), `**Random weight:**` (0-9, 0 excludes it from `--rotate`), `**Prompt protocol:**` (a rule that layers on top of the shared one). Only `**Status:**` is meant to be edited; the advisor records progress via `set-status`.

A body is the single fenced `text` block in the section — a second fenced block is an error, not a fallback. Seven blanks fill automatically; any other `{name}` the tool refuses to invent and prints the command to supply instead:

| blank | source |
| --- | --- |
| `{method}` | the chosen row's method name |
| `{index}` | its `#` in the matrix |
| `{section}` | the table letter (`A`..`R`) |
| `{state}` | its verdict cell, verbatim |
| `{page}` | its method page, or the page its slug suggests |
| `{target}` | its key — `{section}{index}` |
| `{references}` | the pins relevant to that row: the `always` set plus any whose `name` or `topics` keywords appear in the row's line |

`next` picks the first eligible row of the template's target class the library's own ledger (`.ferrox/slices.log` for the ordinary default library, `.ferrox/slices-<tag>.log` for any other) has not served to *this* template, renders the body, delivers it, and then records the row unless `--no-ledger` is set; a missing-input refusal or a failed handout write records nothing. A row is eligible when it fills every required matrix input and selected add-on the caller has not supplied, so an empty cell can make it skip to a later row. Calling `next` again moves on; the default memory suppresses a template it just handed out, `--memory 0` forgets that window so the next call may continue the same template's rows, and `--rotate` draws by weight rather than rank. For `open` templates the candidates are ordered by gap rank, then high priority, then whether the row already links a method page; automatic selection skips `not-scheduled` rows, though `--row` still names one. `implemented` and `all` templates are offered in plain matrix order.

A row can also be named by hand — `--row A13` for its key, `--row 13` for its number, `--row quic` for part of its method name — and `rows` lists the matrix. A template draws only a row of its own class, so an open template refuses a shipped row and names the templates that take it.

A row's verdict is read from its state cell alone: `implemented`, `in tree`, or `both roles` with no `planned`/`not carried`/`not parsed`/`refused` negation beside it. Everything else is open, including a half-role. Neighbouring columns never flip a verdict.

Add-ons are one line each: `**Add-on — <slug>:** <extra instruction>`. Paths under `upstream/<name>/` are pinned reading copies fetched by `scripts/fetch-upstream.sh`; they never appear in `**Touches:**` and are never committed. `{references}` is drawn per row from that pin file — every `always` pin, plus every pin the row's own line names or hits one of its `topics` keywords, so a QUIC row asks for quiche and an unrelated row does not, with the whole list as the fallback when nothing matches — which keeps "compare against the best implementation" reading the pins rather than a hand-kept sentence.

Every handout carries the shared protocol, so a template says only what it adds: `check` refuses a `**Prompt protocol:**`, body or add-on that runs five content words with the protocol, and warns when two templates echo each other for six. Code spans, `{blanks}` and function words are not counted as evidence.

## Shared protocol

```text
You are working on Ferrox, a from-scratch proxy core. Two claims define it and both are checked: output is byte-identical to the implementation it replaces, and it is not slower at any measured length. A change that alters the bytes on the wire to buy a syscall is neither, and it does not land.

Ferrox is a superset: any well-formed config xray-core accepts must run here, including every surface the tree currently refuses. An unimplemented surface is planned work, never a terminal verdict; a refusal is a temporary reason to close the gap, and the slice that reaches it removes it. Only malformed or unsafe input fails closed.

The bar is the best implementation, not a working one. References are the pins in `upstream/pins.toml`: learn how each does the thing, find where it copies, branches, refills, or allocates needlessly, and write the smaller, faster, leaner thing that is bit-identical. Rewrite, do not copy — no upstream line or test enters this tree.

Trust neither this tree nor a reference to have found the floor: hunt the wins, try ideas no template names, keep only what a count proves, and revert a measured regression with its arithmetic on the page. One fewer proven operation is a win worth landing. Faster, safer, leaner, or it does not land; counts prove, durations suggest.

A claim is either checked by something that runs or it is not made — name its checker, or say in the same sentence that no such check exists. A count nobody has measured stays `UNBLESSED`, never quoted as a figure, and a number enters `scripts/expected-ops.txt` only after reading the diff that moved it. A copy or allocation is proved by pointer identity, not by reading the code: the returned slice's base lies inside the caller's buffer, that buffer's pointer does not move, its capacity does not grow. A byte-level test cannot see a copy — the bytes are identical either way.

Before landing a rewrite, ask what the worst input does: the length that is not a multiple of the vector width, the window already full, the cursor this change moves. The arithmetic finds the regression a green suite hides.

Local before every push: `./scripts/check.sh` runs fmt, clippy, doc, the policy checks, exact operation counts, and the workspace tests. Never local: anything connection-dependent — benchmarks, parity, upstream suites, Miri — because every contributor sits behind a VPN and a proxy, so a local dial measures a tunnel, not the reference. Where the counting userspace cannot be provisioned the count stays `UNBLESSED`, never a silently skipped gate, and no slice waits on `ops.yml` for it.

Simpler with less code wins every tie at equal performance: no abstraction with one implementor, no second way of doing something, no debt left for a later slice. Unsafe only for a measured win; if the safe form ties, the safe form ships.

Report tersely: what changed, what was measured with numbers, what is still open. A slice that fails is worth more than one reported done that quietly skipped half its gates. Fixes leave no trace — one line of comment per item at most, no TODO, no changelog.

Do not widen the slice. If it exposes a larger problem, tighten an existing prompt here by a surgical edit of ten words at most; add no new template, add-on, or prompt.
```

## P1 · Land an open method row

**When to use:** The matrix has a row the tree does not implement, and moving it from planned or one-role-only to shipped is the largest single step towards parity with the references; a surface the tree currently refuses is planned work, not a scope boundary.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** open
**Gates:** `cargo test --workspace --all-features`; CI: `conformance.yml`; CI: `bench.yml`; CI: `parity.yml`
**Random weight:** 8

```text
Implement {method} — matrix row {index} of table {section}, currently "{state}". Finish the whole row, both roles where the method has two. Take the best idea from each of {references}. Prove byte-identity before any speed claim, and where a reference ships a suite with a seam to inject `ferrox-app`, run it unmodified in `conformance.yml`.
```

**Add-on — both-roles:** If the state cell concedes one role only, the missing role is the whole slice.
**Add-on — refused-by-name:** A config naming an unimplemented surface refuses with a reason for now; that refusal is a temporary gate, and this slice removes it. Never treat a refusal as scope or as the end state.
**Add-on — connect-ip-terminate:** When the row is MASQUE CONNECT-IP (matrix row 21) the client and the two-way codec are already shipped — the Foxy `h3` lane dials over HTTP/2 and quiche HTTP/3, and `crates/ferrox-core/src/foxy/connectip.rs` writes and reads every capsule (`address_assign_encode`, `route_advert_encode`), proven inverse to their readers byte-for-byte. The two open roles are each their own slice: (a) a proxy that *terminates* a tunnel — read `upstream/xray-core/transport/internet/masque/connectip/` and `upstream/mqvpn` — whose open work is the address pool and IP/ICMP forwarding to a privileged `tun`, which no share-link row reaches; (b) a standalone `Carrier::Masque` VLESS outbound off the account. Land the client row, then route each of those as a separate `next`; never fold a privileged device write into a codec slice.
**Add-on — pattng-tls-shaping:** For PattNG `unsafe-*`/`cipherSuites`, read `upstream/pattng/V2rayNG/app/src/main/java/com/v2ray/ang/core/TlsSettingsCheck.kt`: unsafe is the stock stdlib hello honoring the list, not uTLS. Rows 18/19/4 landed the parse and flags; the open rung is alpn-as-written on every TLS outbound. Gate `cipher_suites` per field, not the whole hello.
**Add-on — pattng-tls12-advertise:** Row 18's TLS 1.2 half is on two lanes: rustls (TLS 1.3 trio + six ring AEAD ids) and BoringSSL for CBC/static-RSA/`000a` when the list names a suite ring lacks. Ceilings: mixed 1.3+1.2 lists match only the 1.2 ids, ECH keeps rustls, the legacy lane has no session cache, and RC4/3DES/`003c` reach neither.
**Add-on — tun-native-device:** Row 32's consume path landed: `tun.rs` reads whole packets off `FERROX_TUN_FD`, stream demux dials through `serve_connect`, datagram demux rides one SOCKS UDP association, and `scripts/tun-oracle` diffs dial sets. Open slices: ICMPv6 echo, neighbour/multicast discovery, ICMP errors for relayed flows, over-MTU/empty datagrams, and the privileged open (compile-checked only, no `CAP_NET_ADMIN` runner).
**Add-on — finalmask-refused-types:** Row 34 ships `fragment` and refuses `header-custom`, `sudoku` and `xmc`; each is its own slice with a scripted byte differential against the pinned Go writer (no pinned interop row covers them). Order: `sudoku`, `header-custom` (do not fork `carrier-httpheader`), `xmc`. UDP mask families are a second row.
**Add-on — hysteria-obfs-masquerade:** Rows 20/149 reach the UDP lane, salamander/gecko, port-hop and masquerade. Ceilings: port-hop + gecko is refused at `connect`; `brutal`/`up_mbps`/`down_mbps`/`bbr_profile` are accepted-and-ignored (no wire byte, no brutal sender in quiche); sing-box-only `realm`/STUN discovery is its own slice.

## P2 · Make a shipped method faster and leaner

**When to use:** A row is implemented — the standing hunt for maximum throughput and minimum CPU now applies to it.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml; CI: `compare.yml`
**Random weight:** 9

```text
Move {method} — matrix row {index} of table {section}, state "{state}" — towards the best known implementation among {references}. Throughput and leanness at bit-identical output: fewer retired instructions, fewer copies, fewer branches. Think in eliminated work, not added code: factor the math, fuse passes that touch the buffer twice, hoist per-record dispatch, narrow a parse that re-checks what a caller already checked. Re-measure the exact count with `scripts/count-ops.sh`.
```

**Add-on — shared-codec-scope:** When the row's codec lives in a `ferrox-core` module no page owns because a second method calls it too (`early_encode_into` is also `proxy.rs::b64url`'s encoder for a REALITY x25519 key), do not add that module to the page's `paths` or `symbols` to narrow the run: a claim narrows the plan to one carrier and hides the other caller. Leave it shared, take the wide plan, and name the second caller in the page's `CI scope` prose so the next reader knows why the run is wide rather than assuming it is sloppy.
**Add-on — handshake-entropy:** A carrier's per-connection randomness is a syscall the data path never sees: the ws client asks `getrandom` for the 16-byte key on every dial while `fresh_mask` already pulls 512 bytes at a time into a thread-local. Batching the key the same way is real, is that carrier's own row rather than the row whose handshake happens to ride in the same buffer, and is gated on the syscalls per connection over a loopback dial — so route it to that row's next `next` instead of folding it in.
**Add-on — carrier-stage-drop:** A `BufReader` around a carrier is a stage: downlink bytes cross user space twice and the carrier's record caps the socket read, so the stage's capacity is invisible. Audit the gate before the code; the counter must sit between carrier and codec to see the ask.
**Add-on — head-buffer-round:** `proxy::kept_head_rounds` is shared by ws/xhttp/httpupgrade/httpheader: `HEAD_ROUND=512`, doubling rounds, so a normal head reallocates. Two separate slices: pre-size the first round (allocation count held steady), or pool the head `Vec` (single-thread ownership; the per-reader drop-to-`Vec::new()` is already safe).

## P3 · Take a shipped method's memory footprint down

**When to use:** A row is implemented and its steady-state allocations, buffers, or per-record copies still scale with traffic rather than with the connection.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml
**Random weight:** 6

```text
For {method} — matrix row {index} of table {section} — remove work that is generated and thrown away: a per-record buffer that could be reused, a second copy of a payload already in the caller's buffer, a zero-fill before a read that overwrites every byte, a `Vec` that reallocates under steady traffic. Gate the allocation claim on the counting allocator asserting a steady allocation count over a push/drain cycle, and the buffer-growth claim on `capacity()` held steady over the same cycle; name the pass that got worse if there is one.
```

**Add-on — pool-owner:** When one buffer is filled by one thread and drained by another, the pool lives in the object both touch; the parse order respects that single owner.
**Add-on — tls-config-once:** A rustls `ClientConfig` is rebuilt on every TLS dial (`RustlsProvider::connect` → `config()`), where xray's `GetTLSConfig()` and sing-box's transport both build theirs once per outbound and hand the same value to every connection; memoise the built `Arc` by the config's security-relevant bytes (roots, alpn, pins — never `server_name`, which is per-connection) so a repeat dial pays a key clone and an `Arc` bump instead of re-parsing every DER and rebuilding the verifier and cipher Arcs, gate it on the allocation count in `ferrox-core`'s counting test binary, and because it sits in the shared session layer every `*-tls` carrier funnels through, it is its own slice rather than one method row's hunt.
**Add-on — per-datagram-aes-schedule:** Every AES-GCM datagram carries a fresh salt, so `Cipher::from_master_key` runs HKDF-SHA1 and boxes a whole new `Aes128Gcm`/`Aes256Gcm` engine — key schedule and GHASH table — per datagram. A per-thread cipher is impossible (the key *is* the salt) but a rekey in place on the engine already in hand is not, and it would remove the per-datagram `Box` and the schedule build. It is not one UDP method row's hunt: the seam is a rekey surface in `crates/ferrox-core/src/aesgcm`, whose scope covers the record layer, so it lands as its own slice gated on an allocation count in `ferrox-core`'s counting binary held steady over a datagram stream, never on a wall clock.
**Add-on — arena-header-gap:** KCP's arena reserves an 18-byte header gap that `write_data_header` overwrites before read — a zero-fill-before-overwrite. Removing it needs `Vec<MaybeUninit<u8>>`, rippling through `emit_slice`, `trim`/`drain` and the pointer witness; gate on `SendingWindow::push` retired instructions (Linux CI) plus Miri, never a wall clock. Stays in row 14 until then.

## P4 · Prove a shipped row bit-identical to the references

**When to use:** A row is implemented but its byte-identity is argued from the source rather than swept against the pinned copy — the check that must run before any speed claim on that row.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `parity.yml`; CI: `bench.yml`; `cargo test --workspace --all-features`
**Random weight:** 4

```text
For {method} — matrix row {index} of table {section} — replace the argument with a differential sweep against the pinned reference: every length and every offset the method can see, both sides of every group boundary where a vector rung could overrun. Keep the key or nonce material such that a permuted implementation cannot pass. Name both backends in every row of the report; if one build dispatches to scalar against the reference's vector path, say so.
```

**Add-on — forged-input:** A malformed or wrong-tag input must leave the buffer exactly as it found it; a sweep that only feeds valid input proves the happy path.
**Add-on — query-rewrite-spelling:** When the reference strips a query parameter and re-encodes what remains through Go's `url.Values.Encode()` — which sorts by key and re-escapes — the rewrite's *spelling* is part of the wire, and a rewrite that keeps the original order keeps different bytes. No checker in this tree sees it while every server compares `URL.Path` without the query (`request_path` strips it here too), so the divergence only surfaces behind a proxy that routes on the full URI. Prove it or name it: a differential over unsorted multi-parameter paths against the pinned `url.Values` encode, or an explicit sentence on the page saying which spelling ships and why no reference peer can tell.

## P5 · Rewrite one parser or framer to the best form

**When to use:** The bytes of a method are right but the code that produces or reads them is not the smallest, cheapest thing the references imply.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** all
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `compare.yml`
**Random weight:** 5

```text
Read the parsing and framing for {method} — matrix row {index} of table {section} — against {references}, and rewrite this tree's version cheaper at the same bytes. Prove the validator by the same counts as the parser — checking code is code too, and it runs on every frame.
```

**Add-on — seed-fuzz:** Feed untrusted bytes through every entry point on a seeded corpus and assert no panic.

## P6 · Bring a method page up to the four-number standard

**When to use:** A row's data path is real but its page under `docs/function` is missing, or states counts with no checker named.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** all
**Gates:** `./scripts/check.sh`; `bash scripts/check-method-docs.sh`; CI: `ci.yml`
**Random weight:** 3

```text
Write or bring up to standard {page} for {method} — matrix row {index} of table {section}, state "{state}". Every connection-method page carries the same four numbers — ops, syscalls, memory copies, time — each with the name of the thing that produces it, a `graph TD` of the data path, and what was removed against {references}. The numbers live in exactly one place, `scripts/method-counts.txt`; the page cites the manifest row and does not keep a second copy. Name what was not removed as openly as the wins. Carry the scope block with the page: `paths` for the files it owns, `symbols` for every item of a shared file that is its own — a rung in `proxy.rs`, a resolver in `config.rs` — because a method whose code lives in the relay is recognised by nothing else, then `scenarios`, `oracle` and `go`, and `engines` only where its own cell already showed a comparator serving it nothing.
```

## P7 · Wire a conformance seam for a shipped row

**When to use:** A method is implemented here and a pinned reference ships a suite for it, but nothing runs that suite against `ferrox-app`.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `conformance.yml`; `cargo test --workspace --all-features`
**Random weight:** 3

```text
Give matrix row {index} of table {section} — the implemented method {method} — a conformance leg: find the suite in {references} that exercises it, add, enable or widen the `[sources.*]` seam in `upstream/pins.toml` that injects `ferrox-app`, and run that suite unmodified in `conformance.yml`. Prove the leg reached this binary — name the seam and the test count. Green here plus red there is not done; if no `seam` in `upstream/pins.toml` reaches this binary, say so plainly.
```

**Add-on — pin-honesty:** Any pins edit carries the real rev from a resolved ref; never fabricate one to satisfy a gate.

**Add-on — seamless-byte-row:** When the reference tests are in-package Go with no binary seam (row 35), name the absent seam and gate byte-identity in-tree with recorded request bytes over a loopback fake. The next seam is the reference's `local` store over a shared directory: no network, no token.

## P8 · Find the work the tree does and discards

**When to use:** The standing RAM/CPU hunt on a shipped row — where something is computed, filled, or locked and then thrown away or re-done before the value is ever used.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml
**Random weight:** 5

```text
Audit the hot path of {method} — matrix row {index} of table {section} — for work done and discarded: a value computed then overwritten before anything reads it, a lock taken twice for one wait, a buffer sized for the worst case on the common small one. For each finding, remove it or prove it load-bearing against the leanest shape in {references}. Before writing a test that reconstructs a quantity, look for the counter already lying around as state.
```

**Add-on — write-all-slices:** Fix `RecordAlignment::write_all_slices` at the provider layer to use `write_vectored`, override it at every wrapper in the caller's path, and hand the framer's head/body/trailer as three slices. Per-part `write_all` is right on a raw stream and wrong under TLS.

## P9 · Prove a vector rung on the ISA it compiles for

**When to use:** A SIMD or width-generic rung is in the tree and a CI runner whose architecture is named has not yet run the differential on it.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `bench.yml`; CI: `safety.yml`; `cargo test --workspace --all-features`
**Random weight:** 3

```text
For {method} — matrix row {index} of table {section} — confirm each width backend of its vector rung means what it claims on a runner whose architecture the job names: lane count, chunk-to-block layout, the store that writes consecutive output bytes with no transpose. The layout is the part worth reading twice — a backend that produces the right bytes through the wrong layout is right by accident, and the next change makes it wrong. Make the layout a named constant or an assertion, not a comment.
```

**Add-on — miri-boundary:** Miri interprets the safe-Rust ladder but not `core::arch` intrinsics; say which rungs Miri covered and which the differential covers instead.

## P10 · Prove the engine does less at a length nobody measured

**When to use:** A rung's counts are argued rather than blessed, or a length boundary has never been swept — turning an `UNBLESSED` claim into a number a runner reproduces.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** CI: §ops.yml; CI: `bench.yml`; `./scripts/check.sh`
**Random weight:** 3

```text
For {method} — matrix row {index} of table {section} — measure the operation count of its hot symbol with `scripts/count-ops.sh` across every length and boundary the method reaches; read `scripts/method-ops.txt` for the CI number before deciding anything. A connection-dependent count belongs to `ops.yml`, not to a laptop run. If the runner cannot provision the counting userspace the count stays `UNBLESSED`: never quote a figure, never wait on `ops.yml` for it.
```

## P11 · Make a test that loses to the runner fail on a defect

**When to use:** A test for a shipped row goes red one run in several and green otherwise — it is asserting a quantity the scheduler or the runner moves, not a property of the code.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`
**Random weight:** 4

```text
Take the flaky test on {method} — matrix row {index} of table {section} — and make it fail only on a defect. Drive the counted quantity from an in-memory stream that always answers the whole buffer, where the number is exact; over a real socket assert only the bytes. A loopback test cannot gate a syscall count and a scheduler-dependent count is not a gate at all — move the assertion to where it is deterministic and leave the socket test proving the wire.
```

**Add-on — replay:** Seed any corpus-dependent test so a red run prints the case that broke it and replays on any machine.

**Add-on — harness-bound:** Read `harness_ceilings_mib_s` before blaming an engine: throughput at a small fraction of it for every engine is the instrument's bound (e.g. all upload cells at 616 MiB/s against a 4294 MiB/s pipe). A ceiling row is one generator into one reader; relay rows are two hops, so read it as a floor.

**Add-on — cpu-split-tick:** `check_split` drops a run when `cpu_user + cpu_sys` differs from `cpu_millis` by >1 ms; Windows cannot agree because each half rounds its own tick pair, so a run can lose up to 2 ms and a cell under two pairs reports `UNPROVEN`. Budget the rounding in the split check rather than dropping pairs.

## P12 · Collapse a duplicated walk, ladder, or dispatch to one copy

**When to use:** The same config walk, header parse, ladder fork, or relay dispatch is written out in more than one file, and a change to one silently diverges from the others.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** all
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `compare.yml`
**Random weight:** 4

```text
Find where the bytes or dispatch of {method} — matrix row {index} of table {section} — are written more than once across the carrier and proxy files, and fold them into one shared helper, not a trait with one implementer. Nothing on the wire or in the count moves; the line count and the divergence risk go down. Where a fork exists only because two paths disagree on one boundary, make them agree and delete the fork.
```

**Add-on — retire-dead:** A knob or code path with no consumer gets a caller in a test or is deleted — do not leave it named-but-unreachable.

## P13 · Bound a loop or handshake the socket currently ignores

**When to use:** A handshake, relay, or server drive can spin or block on a peer that goes silent — the hang is reachable in principle and no deadline stops it.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; CI: `safety.yml`
**Random weight:** 5

```text
Give {method} — matrix row {index} of table {section} — every wait a deadline the socket cannot ignore: bound the handshake, the relay read, and the server drive that spins on an idle peer. Test it by parking the peer and asserting the loop stops within the budget, not by sleeping and hoping. A budget a peer can exhaust must refuse cleanly, not truncate or silently drop what is in flight.
```

**Add-on — deep-retry:** A carrier whose reader loops on timeouts (gRPC, xHTTP, VMess, Shadowsocks) needs the budget inside the loop; record it as a row. `proxy::read_exact` treats `is_timeout` as retryable, so a caller can spin forever; take the budgeted shape from `read_exact_head`.

**Add-on — flow-wait-with-no-bound:** In `poll_relay`, `drive` waits on both directions with no bound and `Worker::push` drops the flow when the queue lock is poisoned, so a worker parked inside `copy_all_memcpy` starves every flow queued behind it and their waits print nothing; bound the flow the way `RELAY_JOIN` bounds a leg, and prove it by parking one worker and asserting the flows behind it still end.

## P14 · Put a layer where the references put it

**When to use:** A method's bytes are right but the security layer, framing, or session lives at a different depth than every pinned reference puts it, so the next row that reuses it cannot.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `parity.yml`
**Random weight:** 3

```text
Compare where {references} place the layer for {method} — matrix row {index} of table {section} — against where this tree places it, and move it to match if the references agree and this tree does not: the security layer outside the carrier, the session above the transport, the framer below the record. Prove the move by the byte-differential still passing and the seam a later row needs now existing; a move that shifts a byte or a count is a method change, not a move.
```

## P15 · Give a non-matrix surface a working seam

**When to use:** Engine-adjacent capability the matrix does not carry a row for — the account plane, an upstream-proxy chain, TUN/VPN modes — that parses or is described but is not reachable from a config or a test.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Targets:** none
**Gates:** `cargo test --workspace --all-features`; CI: `conformance.yml`
**Random weight:** 2

```text
Take one engine-adjacent surface {references} carry that this tree names but cannot drive — the account plane, the upstream-proxy chain, or a TUN/VPN mode — and give it a working seam: wire it to a config path or a test entry point, name the reference it matches, and prove one round-trip in CI. If it genuinely cannot be reached from this tree's shape, say why plainly in the place a reader would expect the capability rather than leaving it silently half-described.
```

**Add-on — server-engine-surface:** The pinned ZeroNet tree carries server surfaces this tree cannot drive — reverse bridge/portal (`zero-runtime/src/reverse.rs`), PROXY-protocol parsing on an accept (`zero-protocol/src/proxy_protocol.rs`), the WireGuard inbound (`wg_server.rs`), transparent `SO_ORIGINAL_DST`/TPROXY dials (`zero-net/src/transparent.rs`). README table N rows 169–178 and `docs/method-superset.md` name each with its reference paths; take them one row per slice, seam first.

## P16 · Deep-optimization hunt: beat every reference, or prove the floor

**When to use:** The open-ended, high-effort pass on a shipped method — not the one clean win, but the hunt for an order-of-magnitude one, assuming the current implementation and every reference still leave the breakthrough undiscovered.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml; CI: `compare.yml`; CI: `parity.yml`
**Random weight:** 9

```text
Make {method} — matrix row {index} of table {section} — faster, leaner and more functional than {references} put together. This is the open-ended pass: not the one clean win but the order-of-magnitude one, so push each winner to the end instead of stopping at the first.

Think like a math paper, not a patch: change the basis or the order, factor, recast the computation, and prove the new form equivalent before shipping it. Mine every lens — algebraic structure and hot inner loops; bit tricks and SIMD across every width the ladder runs; microarchitecture (cache locality, branch prediction, IPC); I/O (batching, zero-copy, vectored and kernel offloads, ring buffers, lock-free handoffs, segment offloads); outright elimination of ops, copies, allocations, syscalls, locks, atomics, branches, zeroing, checks and dead code nothing reads; and the method-specific tricks — codec tables and DFA walks, one's-complement folding where the modulus allows, varint and padding shapes, multiplexing, and the crypto primitives' hardware paths.

Prove the win or discard it: the exact count from `scripts/count-ops.sh` where the runner can provision it (`UNBLESSED` otherwise), and the benchmark gate in CI. Re-measure the byte-differential before and after — bit-identical means the block, byte, counter and panic-threshold counts are unchanged, not only the output. Where the wire shape is fixed, say so.
```

**Add-on — novel-idea:** An idea none of the lenses above names is welcome; it is proved the same way or discarded.
**Add-on — floor-proof:** If the hunt finds nothing above noise, prove the floor: record the ideas tried, each one's count, and what a reader should try next — an argued floor beats a quiet stop.
**Add-on — many-rounds:** Land one proven win per commit and keep hunting; a single diff that "optimized the method" is the end of one round, not the end of the slice.

**Add-on — httpupgrade-handshake-floor:** Row 17's landed rounds removed the payload round trip, a write syscall and TLS record per dial, request-buffer slack/growth, 22 bytes off the status compare, the Shadowsocks dial's extra round trip, and the `peek` re-read (`read_http_head_kept` keeps the tail; `UpReader` walks it by cursor). Remaining: the xHTTP accept loop still owns a tail buffer; `peek_head_rounds` stays for the `http` CONNECT front and Shadowsocks. The five-piece gather was refused because rustls `coalesce` heap-allocates past four `IoSlice`s.

## P17 · Hunt and fix the concurrency, timing and flakiness bugs

**When to use:** The engine has races, stalls and flaky tests — half-closed races, duplex deadlocks, timeouts that never fire, buffer-ownership races, tests that lose to the scheduler — and each one is a defect to find, prove, and fix one at a time.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; CI: `safety.yml`; CI: `conformance.yml`; CI: `bench.yml`
**Random weight:** 8

```text
Find a concurrency, timing or duplex defect in {method} — matrix row {index} of table {section} — and fix one: a half-closed race, a full-duplex stall, a timeout or deadline the socket can miss, a buffer-ownership or pool race, a wakeup lost behind a cursor, or a test that goes red one run in several. One defect per slice.

Reproduce before fixing: land a test that is red on the defect and green after it, and keep the red case in the suite — a bug read off a symptom is a guess until that test exists. Where a timing window is genuinely involved, drive it from an in-memory stream or a controllable clock, never a wall-clock sleep or a real socket. A flaky test is itself the defect's witness: pin what it actually observes.

Prove the fix under the tools that see these bugs: Miri for the memory and aliasing races, the byte-differential for the wire, CI conformance and benches for the connections. Never paper over a race by moving a wire byte or a datagram boundary; fix the ordering or the ownership, and say which.
```

**Add-on — race-hunt:** Audit where one buffer is touched by two actors, where a cursor or counter can lag what a read consumed, and where a window can fill; name the invariant each guard holds.
**Add-on — half-close:** The close edge is the usual bug site — check who shuts which direction, what the peer sees, and whether a pending read can outlive its writer.
**Add-on — shared-close:** Where both directions of one relay tear down through a single shared `close` closure, no per-direction half-close is expressible and whichever thread finishes first aborts the sibling's still-open read; carry two directional closes per site, and where a carrier has no half-close primitive at all, name that limit rather than sweeping `Both` to `Write` blind.
**Add-on — withheld-answer:** A server may hold its handshake answer until it sees client payload — xray flushes its buffered response on the first downstream write, zeronet's `HeaderFirst::hold` waits for it outright — so a client that stops sending to wait deadlocks both ways; pump the upload leg during the answer wait and hand it back before the session relay. Where the answer read shares one session lock with its writer (TLS halves, mux, the UDP uplink) the leg has to yield that lock first, so record those arms as rows instead of bolting a pump onto a locked half.
**Add-on — unread-close-rst:** Where a peer's answer is already on its way and that peer still holds payload it never read, ask what its close sends.
**Add-on — padded-data-credit:** The xHTTP h2 lane credits a padded `DATA` frame at wire length (Pad Length + Padding, RFC 7540 6.9). The gRPC and Foxy lanes still credit only `len - first - pad`, so a strict peer loses `1 + pad` octets per frame; each lane is its own slice with a `WINDOW_UPDATE` witness. Foxy first needs the parser to hand over the frame length.
**Add-on — parked-leg:** A relay that tears down its *own* direction and then joins its sibling wakes nobody: shutting one half of a socket does not release a `recv` blocked on it, so the pooled leg sleeps until the join budget burns, the give-up prints, and the worker is lost for the life of the process while the next flow spawns another. Audit every join the way the close edge is audited — ask what ends the leg that is *not* on the calling thread, and land the witness as a red-then-green test that the flow whose partner ended returns inside the park, not inside the budget.
**Add-on — transient-ref-loss:** A loaded runner can lose the reference's runs to `ENOBUFS`/`EPIPE`, leaving too few pairs and a false regression. Never report a short transfer; add a bounded retry with fresh output per attempt, and witness it with a stream that drops the reference's first attempts.
**Add-on — own-baseline:** A row comparing two in-tree paths claims a difference that can sit under runner noise. Count the work each shape does at that length first: the fused and split seal generate the same blocks once a pass fills, so the row measures a call, while under a pass the headed shape wins. Gate only lengths a code change can move; never move a threshold to go green.

## P18 · Give a decision the engine already implies its owner

**When to use:** The engine classifies failures, negotiates capabilities or probes alternatives somewhere, but no component acts on that knowledge — the recovery ladder, the climb or the probe is implied by the design and unwritten in the code.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `conformance.yml`
**Random weight:** 4

```text
{method} — matrix row {index} of table {section} — already implies a decision the engine does not own: which failure is worth retrying versus terminal, what it climbs or descends when one path stops answering, what it asks the peer before committing to a pooled or multiplexed shape, when a credential or pass latches rather than retries. Read how {references} make the same call, then give this one a named owner and a bounded policy: the taxonomy row that decides, the component that acts on it, the counter or deadline that bounds it.

Prove the decision, not the intent: a test that drives each failure kind and asserts the ladder takes the branch it names, and — where the policy depends on what the peer says — a test that answers differently and asserts the engine follows the answer. A probe that costs a round-trip on every flow is a count change; state what it costs and what it saves.
```

**Add-on — bounded-cost:** Name the worst case of the probe or retry — rounds, bytes, latency — and cap it, so recovery cannot become a stall.
**Add-on — one-owner:** One component decides and one acts; a policy consulted in two places diverges, so fold the second into the first.

## P19 · Make a stall name itself from inside the engine

**When to use:** A hang is only visible from outside — `watch-test.sh` reads procfs wchan on Linux runners and nothing elsewhere, and a thread parked in the engine carries no name of its own — so a stall in the field, on macOS, or on Windows reports a pid, not a wait.
**Status:** doing
**Leverage:** 5
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; `cargo test --workspace --all-features`; CI: `safety.yml`; CI: §ops.yml
**Random weight:** 7

```text
{method} — matrix row {index} of table {section} — parks a thread in waits the engine knows about by name but the running process cannot say: every cadence lives in `crates/ferrox-app/src/budgets.rs`, yet nothing at runtime reports which named wait holds which thread on which fd for how long. Give the engine its own wchan: a census next to `budgets.rs` where a wait registers its name, the fd it blocks on and the deadline it armed, deregisters on return, and dumps as per-thread lines on demand — from a test, a signal, or the CI harness.

Gate the census on a build shape with no production traffic, the way `count-ops.sh` gates its binary: the hot relay path must not pay for a map a stall hunt reads once. Prove the census by parking a wait on an in-memory stream that answers nothing and asserting the dump names that wait, its fd and a waited-for duration — a test that only compiles the dump sees the API, not the thing it claims. The engine's waits are the table; a row of that table with no census entry is the finding, and the census earns its keep the first time a P17 or P13 slice is written from a dump line naming the wait rather than from a post-mortem.

Report the per-wait cost the census adds where it is reachable, or state that the gated shape makes it zero and name the gate that proves it.
```

**Add-on — stall-to-name:** Extend `watch-test.sh`: before it kills a stalled test binary it sends the stop and re-reads the log once, and the workspace test harness answers that stop by dumping the census. A stall then prints the engine's wait names beside the procfs lines, on every OS — procfs sees the kernel, only the census sees the engine.

**Add-on — starved-leg:** A dump showing one leg of a relay in `read` and its partner in nothing is a join that outlived its bound; check it against `RELAY_JOIN` and the leg-witness tests before naming it a peer problem.

**Add-on — sys-attribution:** `ferrox-bench`'s kernel tally cannot price a Rust relay's sys time: `/proc/<pid>/io` counts the `read`/`write` paths, and std's socket legs — `send`/`recv` — never appear there, which the `ps` witnesses show against a child that writes a file. Attribute the residual per thread instead: sample `/proc/<pid>/task/*/stat` for who holds the `stime`, then name the asks from the census' waits, and report a `0` per-GiB row as the instrument's gap rather than as a crossing that cost nothing.

**Add-on — rest-of-the-table:** Eight of the ten named budgets still have no census entry — `dial`, `handshake`, `headArrival`, `relayQuantum`, `udpIdle`, `payloadGrace`, `goawayGrace`, `carrierProbe` — nor do the constants that pace a loop. Most arm sites hold the deadline and then do the blocking call in the same scope, so a row there costs one registration around that call rather than one inside the funnel; a leg through the shared relay half first needs its descriptor named, because a `dyn Read` reaches the wait with no fd to report.

## P20 · Scale the parameter surface without growing the app file

**When to use:** A knob a reference ships is either unreachable from this tree's config or is plumbed ad-hoc through the app monolith, so adding the next one costs more of the same accretion rather than a section; the superset rows (README table N 116–124) all land through this shape.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Targets:** implemented
**Gates:** `./scripts/check.sh`; `cargo test --workspace --all-features`; CI: `conformance.yml`
**Random weight:** 6

```text
{method} — matrix row {index} of table {section} — gains its user-settable parameters by carving, not by accretion: move the knob group named in its superset row into the section-owned config type that `crates/ferrox-app/src/config.rs` already shapes per plane, give the app one reader of it, and keep the defaults byte-for-byte what the constants in `budgets.rs` say today, so every blessed count holds across the move and `scripts/count-ops.sh` is the witness that the carve moved no work. A runtime-settable cadence is a count change: the page states the new worst case of a wait the peer can tune, and a knob whose default differs from the constant is refused until the matrix and pages say so.

Prove the surface, not the struct: a config-named test per knob that asserts the engine acts on the value it names — a bound that stops a parked wait, a header that appears on the wire, a byte rate the gauge enforces — beside the parse round-trip. A parsed field no component reads is the defect P18 exists to own; check the knob has its actor before calling the row shipped, and record in the superset matrix the row that moved from planned to implemented only when the actor exists.
```

## P21 · Fix and land a P0/P1 regression issue

**When to use:** A P0 or P1 regression issue is open and must be fixed end to end — reproduced, fixed, proven, landed on `main` and closed — before any feature slice continues.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** none
**Gates:** `./scripts/check.sh`; `cargo test --workspace --all-features`; CI: `conformance.yml`; CI: `bench.yml`; CI: §ops.yml
**Random weight:** 0

```text
Phase 1 — Fix and land issue #{issue}, a {priority=P0 or P1} regression. Read the issue and reproduce the failure before editing; work only in a worktree made by `./scripts/new-worktree.sh bugfix-{issue}`. The fix is complete when the defect cannot recur: add a test that is red on the unfixed tree and green after the fix, run it with the gate in `./scripts/check.sh`, then rebase onto `main`, land the fix there, and close the issue with the integration that proves it. Do not leave a smaller defect behind to finish the issue.

Phase 2 — Study upstream. Read the relevant pinned implementations in {references} and find how each handles this path. Name which one is best, and why, with the evidence that decides it.

Phase 3 — Performance passes. First, the focused pass: move the thing the issue touched towards the best upstream form without changing a wire byte: fewer retired instructions, copies, branches, locks and allocations. Re-measure the exact count with `scripts/count-ops.sh` where the runner can provision it; land only the changes that count proves (`UNBLESSED` otherwise), and write down the arithmetic for any regression you revert. Then the open-ended pass: make it faster, leaner and more capable than every reference in {references} together. Carry each winner as far as it goes rather than stopping after one; change the basis or the order, factor, recast and prove equivalence. Mine hot loops and algebraic structure, every SIMD width the ladder runs, cache locality and branch prediction, batched or vectored I/O and lock-free handoffs, and remove ops, copies, allocations, syscalls, atomics, zeroing and checks nothing reads. Sweep the bytes both ways after the change: the block, byte, counter and panic-threshold totals must stay put, not merely agree at one length. Where the wire shape is fixed, say so.

Phase 4 — Before every push, run the shared local gate. Nothing connection-dependent is local evidence; the CI jobs are where a dial, a benchmark and Miri count.
```
