#!/usr/bin/env bash
# One carrier of the ferrox-vs-arman A/B: one pinned edge, one minted pass, one
# origin and payload, alternating the engine each round so a shift in the tunnel
# hits both. The edge is pinned by name and by the one IP both engines dial
# (ferrox `edgeAddress`, arman `SetEdge`), because the catalogue hands out a new
# server per dial and would compare two tunnels, not two engines. The exit IP is
# recorded per engine: the provider allocates egress per session, so the server
# is the same even when the two exits differ. After the rounds, small probes
# record TTFB, jitter and probe loss per engine; a quick probe rejects an egress
# whose TTFB would make the round a measurement of the tunnel, not the engine. Linux only: CPU and peak RSS
# come from /proc. Durations are measured, never gated.
set -euo pipefail

: "${FERROX_BIN:?set FERROX_BIN to a ferrox-app binary}"
: "${ARMAN_TEST:?set ARMAN_TEST to the compiled arman TestFoxyAB binary}"
: "${PASS_FILE:?set PASS_FILE to the minted foxy-pass.json}"
: "${CARRIER:?set CARRIER to h2 or h3}"
: "${COUNTRY:?set COUNTRY to the pinned country code}"

OUT="${OUT:-target/foxy-ab/legs.tsv}"
RES_OUT="${RES_OUT:-target/foxy-ab/resources.tsv}"
PROBES_OUT="${PROBES_OUT:-target/foxy-ab/probes.tsv}"
WORK="${WORK:-target/foxy-ab/work-$CARRIER}"
FERROX_PORT="${FERROX_PORT:-11901}"
ARMAN_PORT="${ARMAN_PORT:-11902}"
ROUNDS="${ROUNDS:-3}"
DOWN_BYTES="${DOWN_BYTES:-10485760}"
UP_BYTES="${UP_BYTES:-4194304}"
MAX_EDGES="${MAX_EDGES:-8}"
EDGE_TTFB_MAX="${EDGE_TTFB_MAX:-0.060}"
LATENCY_PROBES="${LATENCY_PROBES:-15}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-10}"
TRACE_URL="${TRACE_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
DOWN_URL="${DOWN_URL:-https://speed.cloudflare.com/__down?bytes=$DOWN_BYTES}"
UP_URL="${UP_URL:-https://speed.cloudflare.com/__up}"
PROBE_URL="${PROBE_URL:-$TRACE_URL}"

mkdir -p "$WORK" "$(dirname "$OUT")" "$(dirname "$RES_OUT")" "$(dirname "$PROBES_OUT")"
touch "$OUT" "$RES_OUT" "$PROBES_OUT"

FERROX_LOG="$WORK/ferrox.log"
ARMAN_LOG="$WORK/arman.log"
: >"$FERROX_LOG"
: >"$ARMAN_LOG"

FERROX_PID=""
ARMAN_PID=""
EDGE=""
EDGE_IP=""
IP_F=""
IP_A=""

stop() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.5
  done
  kill -KILL "$pid" 2>/dev/null || true
}

stop_ferrox() {
  stop "$FERROX_PID"
  FERROX_PID=""
}

stop_arman() {
  stop "$ARMAN_PID"
  ARMAN_PID=""
}

cleanup() {
  stop_arman
  stop_ferrox
}
trap cleanup EXIT

die() {
  echo "foxy-ab($CARRIER): $*" >&2
  exit 1
}

wait_tcp() {
  local port="$1" pid="$2" end=$((SECONDS + 30))
  while ((SECONDS < end)); do
    kill -0 "$pid" 2>/dev/null || return 1
    if python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=1).close()" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

cpu_ticks() {
  awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

peak_rss_kib() {
  awk '/VmHWM/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0
}

# trace_meta port file -> "loc ip"; the first h3 request after the probe can
# fail in the framing layer, so a fresh session gets three tries.
trace_meta() {
  for _try in 1 2 3; do
    if curl -sS --fail --max-time 20 \
      --socks5-hostname "127.0.0.1:$1" "$TRACE_URL" -o "$2"; then
      awk -F= '$1=="loc"{loc=$2} $1=="ip"{ip=$2} END{print loc, ip}' "$2"
      return 0
    fi
    sleep 1
  done
  return 1
}

# A host:port for every catalogue edge in the pinned country, unless EDGE is set.
edges_in_country() {
  if [ -n "${EDGE:-}" ]; then
    printf '%s\n' "$EDGE"
    return 0
  fi
  "$FERROX_BIN" edges 2>/dev/null | COUNTRY="$COUNTRY" python3 -c '
import json, os, sys
want = os.environ["COUNTRY"].upper()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        edge = json.loads(line)
    except ValueError:
        continue
    if (edge.get("country") or "").upper() != want:
        continue
    host, port = edge.get("host"), edge.get("port")
    if not host or not port:
        continue
    print(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
' || true
}

# resolve_edge_ip host:port -> the bare IP both engines dial, IPv4 first.
resolve_edge_ip() {
  EDGE="$1" python3 -c '
import os, socket, sys
host = os.environ["EDGE"].rpartition(":")[0]
host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except OSError:
        continue
    if infos:
        print(infos[0][4][0])
        sys.exit(0)
sys.exit(1)
'
}

# edge_address host:port ip -> ip:port, bracketed for IPv6.
edge_address() {
  EDGE="$1" EDGE_IP="$2" python3 -c '
import os
port = os.environ["EDGE"].rpartition(":")[2]
ip = os.environ["EDGE_IP"]
print(f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}")
'
}

write_ferrox_config() {
  local edge="$1" edge_addr="$2"
  EDGE="$edge" EDGE_ADDR="$edge_addr" PASS_FILE="$PASS_FILE" \
    CARRIER="$CARRIER" COUNTRY="$COUNTRY" PORT="$FERROX_PORT" \
    OUT_JSON="$WORK/ferrox.json" python3 -c '
import json, os
from urllib.parse import quote
token = json.load(open(os.environ["PASS_FILE"]))["pass"]
host, _, port = os.environ["EDGE"].rpartition(":")
host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
link = "foxy://?host=" + quote(host, safe=":[]") + "&port=" + port
settings = {
    "pass": token,
    "link": link,
    "country": os.environ["COUNTRY"],
    "carrier": os.environ["CARRIER"],
    "exitProbe": "www.cloudflare.com/cdn-cgi/trace",
}
if os.environ["EDGE_ADDR"]:
    settings["edgeAddress"] = os.environ["EDGE_ADDR"]
doc = {
    "inbounds": [{"protocol": "socks", "listen": "127.0.0.1",
                  "port": int(os.environ["PORT"])}],
    "outbounds": [{"protocol": "foxy", "settings": settings}],
}
json.dump(doc, open(os.environ["OUT_JSON"], "w"))
'
  chmod 600 "$WORK/ferrox.json"
}

start_ferrox() {
  local edge="$1" edge_ip="$2" edge_addr
  edge_addr=$(edge_address "$edge" "$edge_ip")
  write_ferrox_config "$edge" "$edge_addr"
  FOXY_DEBUG=1 "$FERROX_BIN" run -c "$WORK/ferrox.json" >>"$FERROX_LOG" 2>&1 &
  FERROX_PID=$!
  wait_tcp "$FERROX_PORT" "$FERROX_PID"
}

start_arman() {
  local edge="$1" edge_ip="$2"
  local token
  token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pass"])' "$PASS_FILE")
  rm -f "$WORK/arman.ready"
  FOXY_AB_TOKEN="$token" FOXY_AB_EDGE="$edge" FOXY_AB_EDGE_ADDR="$edge_ip" \
    FOXY_AB_TRANSPORT="$CARRIER" FOXY_AB_LISTEN="127.0.0.1:$ARMAN_PORT" \
    FOXY_AB_READY="$WORK/arman.ready" \
    "$ARMAN_TEST" -test.run '^TestFoxyAB$' -test.v -test.timeout 0 >>"$ARMAN_LOG" 2>&1 &
  ARMAN_PID=$!
  wait_tcp "$ARMAN_PORT" "$ARMAN_PID"
}

# rate_row engine direction round bytes seconds
rate_row() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$CARRIER" "$1" "$2" "$3" "$4" "$5" >>"$OUT"
}

# download port file -> "code bytes seconds"
download() {
  local code=0 timing
  timing=$(curl -sS --fail --max-time 180 \
    --socks5-hostname "127.0.0.1:$1" \
    -w '%{size_download} %{time_total}' "$DOWN_URL" -o "$2") || code=$?
  echo "$code ${timing:-0 0}"
}

# upload port file -> "code bytes seconds"
upload() {
  local code=0 timing
  timing=$(curl -sS --fail --max-time 180 \
    --socks5-hostname "127.0.0.1:$1" -H 'Expect:' \
    -X POST --data-binary "@$2" -w '%{size_upload} %{time_total}' \
    "$UP_URL" -o /dev/null) || code=$?
  echo "$code ${timing:-0 0}"
}

# probe port -> "ok connect ttfb total", a lost probe being "0 0 0 0". A
# response that arrives is a delivery; a timeout or a reset is the loss this
# layer can see, and TTFB is the latency it adds.
probe() {
  local code=0 timing
  timing=$(curl -sS --max-time "$PROBE_TIMEOUT" \
    --socks5-hostname "127.0.0.1:$1" \
    -w '%{time_connect} %{time_starttransfer} %{time_total}' \
    "$PROBE_URL" -o /dev/null) || code=$?
  if [ "$code" = 0 ]; then
    echo "1 ${timing:-0 0 0}"
  else
    echo "0 0 0 0"
  fi
}

attempt=0
FOUND=0
while IFS= read -r candidate; do
  [ -n "$candidate" ] || continue
  attempt=$((attempt + 1))
  if [ "$attempt" -gt "$MAX_EDGES" ]; then
    break
  fi
  echo "foxy-ab($CARRIER): trying edge $candidate ($attempt/$MAX_EDGES)"
  if ! edge_ip=$(resolve_edge_ip "$candidate"); then
    echo "foxy-ab($CARRIER): $candidate did not resolve" >&2
    continue
  fi
  if ! start_ferrox "$candidate" "$edge_ip"; then
    echo "foxy-ab($CARRIER): $candidate did not serve; see $FERROX_LOG" >&2
    stop_ferrox
    continue
  fi
  if ! read -r loc ip_f <<<"$(trace_meta "$FERROX_PORT" "$WORK/ferrox-trace.txt")"; then
    echo "foxy-ab($CARRIER): ferrox trace through $candidate failed" >&2
    stop_ferrox
    continue
  fi
  if [ -z "$ip_f" ] || [ "$loc" != "$COUNTRY" ]; then
    echo "foxy-ab($CARRIER): $candidate exits $loc at $ip_f, wanted $COUNTRY" >&2
    stop_ferrox
    continue
  fi
  if ! start_arman "$candidate" "$edge_ip"; then
    echo "foxy-ab($CARRIER): arman did not serve on $candidate; see $ARMAN_LOG" >&2
    stop_arman
    stop_ferrox
    continue
  fi
  if ! read -r loc_a ip_a <<<"$(trace_meta "$ARMAN_PORT" "$WORK/arman-trace.txt")"; then
    echo "foxy-ab($CARRIER): arman trace through $candidate failed" >&2
    stop_arman
    stop_ferrox
    continue
  fi
  if [ -z "$ip_a" ] || [ "$loc_a" != "$COUNTRY" ]; then
    echo "foxy-ab($CARRIER): arman exits $loc_a at $ip_a through $candidate" >&2
    stop_arman
    stop_ferrox
    continue
  fi
  ttfb_f=$(probe "$FERROX_PORT" | awk '{print $3}')
  ttfb_a=$(probe "$ARMAN_PORT" | awk '{print $3}')
  if awk -v f="$ttfb_f" -v a="$ttfb_a" -v m="$EDGE_TTFB_MAX" 'BEGIN{exit !(f==0 || a==0 || f>m || a>m)}'; then
    echo "::warning::foxy-ab($CARRIER): $candidate exits $COUNTRY but a probe is lost or above ${EDGE_TTFB_MAX}s (ferrox ${ttfb_f}s, arman ${ttfb_a}s); trying the next edge" >&2
    stop_arman
    stop_ferrox
    continue
  fi
  EDGE="$candidate"
  EDGE_IP="$edge_ip"
  IP_F="$ip_f"
  IP_A="$ip_a"
  FOUND=1
  break
done < <(edges_in_country)

[ "$FOUND" = 1 ] || die "no edge in $COUNTRY carried both engines"
if [ "$IP_F" = "$IP_A" ]; then
  SAME_IP=yes
else
  SAME_IP=no
  echo "::warning::foxy-ab($CARRIER): the pinned edge $EDGE (${EDGE_IP}) exits $IP_F for ferrox and $IP_A for arman; the provider allocates egress per session"
fi
echo "foxy-ab($CARRIER): both engines dial $EDGE_IP through $EDGE; exit $IP_F (ferrox) / $IP_A (arman), same_ip=$SAME_IP"

head -c "$UP_BYTES" /dev/urandom >"$WORK/payload.bin"

HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
f_ticks=0
a_ticks=0

for round in $(seq 1 "$ROUNDS"); do
  if ((round % 2 == 1)); then order="ferrox arman"; else order="arman ferrox"; fi
  for engine in $order; do
    if [ "$engine" = ferrox ]; then
      port="$FERROX_PORT"
      pid="$FERROX_PID"
    else
      port="$ARMAN_PORT"
      pid="$ARMAN_PID"
    fi
    before=$(cpu_ticks "$pid")
    read -r code bytes seconds <<<"$(download "$port" "$WORK/dl-$engine.bin")"
    if [ "$code" = 0 ] && [ "$bytes" = "$DOWN_BYTES" ]; then
      rate_row "$engine" download "$round" "$bytes" "$seconds"
    else
      echo "foxy-ab($CARRIER): $engine download failed: exit $code, $bytes B" >&2
    fi
    read -r code bytes seconds <<<"$(upload "$port" "$WORK/payload.bin")"
    if [ "$code" = 0 ] && [ "$bytes" = "$UP_BYTES" ]; then
      rate_row "$engine" upload "$round" "$bytes" "$seconds"
    else
      echo "foxy-ab($CARRIER): $engine upload failed: exit $code, $bytes B" >&2
    fi
    after=$(cpu_ticks "$pid")
    if [ "$engine" = ferrox ]; then
      f_ticks=$((f_ticks + after - before))
    else
      a_ticks=$((a_ticks + after - before))
    fi
  done
done

for i in $(seq 1 "$LATENCY_PROBES"); do
  if ((i % 2 == 1)); then order="ferrox arman"; else order="arman ferrox"; fi
  for engine in $order; do
    if [ "$engine" = ferrox ]; then port="$FERROX_PORT"; else port="$ARMAN_PORT"; fi
    read -r ok connect ttfb total <<<"$(probe "$port")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$CARRIER" "$engine" "$i" "$ok" "$connect" "$ttfb" "$total" >>"$PROBES_OUT"
  done
done

same_ip="$SAME_IP"
read -r _ ip_f <<<"$(trace_meta "$FERROX_PORT" "$WORK/ferrox-trace-end.txt" || echo "")"
read -r _ ip_a <<<"$(trace_meta "$ARMAN_PORT" "$WORK/arman-trace-end.txt" || echo "")"
if [ -n "$ip_f" ] && [ "$ip_f" != "$IP_F" ]; then
  same_ip=no
  echo "::warning::foxy-ab($CARRIER): ferrox moved from $IP_F to $ip_f during the rounds"
fi
if [ -n "$ip_a" ] && [ "$ip_a" != "$IP_A" ]; then
  same_ip=no
  echo "::warning::foxy-ab($CARRIER): arman moved from $IP_A to $ip_a during the rounds"
fi
if [ -n "$ip_f" ] && [ -n "$ip_a" ] && [ "$ip_f" != "$ip_a" ]; then
  same_ip=no
  echo "::warning::foxy-ab($CARRIER): ferrox exits $ip_f and arman $ip_a after the rounds"
fi

f_ms=$((f_ticks * 1000 / HZ))
a_ms=$((a_ticks * 1000 / HZ))
f_rss=$(peak_rss_kib "$FERROX_PID")
a_rss=$(peak_rss_kib "$ARMAN_PID")
printf '%s\tferrox\t%s\t%s\t%s\t%s\t%s\n' "$CARRIER" "$f_ms" "$f_rss" "$EDGE" "$same_ip" "$IP_F" >>"$RES_OUT"
printf '%s\tarman\t%s\t%s\t%s\t%s\t%s\n' "$CARRIER" "$a_ms" "$a_rss" "$EDGE" "$same_ip" "$IP_A" >>"$RES_OUT"

echo "foxy-ab($CARRIER): ferrox cpu ${f_ms}ms rss ${f_rss}KiB, arman cpu ${a_ms}ms rss ${a_rss}KiB on $EDGE (${EDGE_IP}) exit $IP_F (ferrox) / $IP_A (arman) same_ip=$same_ip"
