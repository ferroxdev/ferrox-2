#!/usr/bin/env bash
# Foxy lane through ferrox-app: one command to connect, check and disconnect a
# laptop, in proxy mode (SOCKS5, HTTP CONNECT, or both) or system-proxy mode.
#
# What this is
#   * starts ferrox-app with a socks/http/mixed -> foxy config under
#     $FOXY_CONF_DIR (default ~/.ferrox, mode 0700), so the account, the pass
#     and the exit country never enter this repository;
#   * signs the Firefox account in, mints the lane pass and dials the edge in
#     the pinned country over whichever carrier the edge answers (auto tries
#     HTTP/2, then HTTP/1.1, then HTTP/3; --carrier pins one);
#   * optionally chains the edge dial through an upstream proxy, which is the
#     only way a network with proxy-only egress can start the lane;
#   * --vpn points the macOS system proxy at the local fronts, so TCP apps that
#     honour it (browsers included) carry the whole laptop through the lane.
#
# What this is not
#   * not a TUN device: this binary has no `tun` inbound and no tun2socks
#     engine (README rows 29 and 58, slice P46), so --tun refuses by name and
#     says why. UDP leaves the device only where an app asks a SOCKS5 proxy to
#     carry it; that rides the lane's MASQUE datagrams, not the device.
#
# Credentials
#   Read in this order: FOXY_PASS, $FOXY_CREDENTIALS (default
#   $XDG_CONFIG_HOME/ferrox/credentials, mode 0600, outside this repository),
#   else typed silently. A copy inside the repository is refused rather than
#   read: the pass is the account's secret, not the tree's.
set -euo pipefail

FERROX_ROOT="$(cd "$(dirname "$0")" && pwd)"
# The measured binary wins when it exists; a tree that has only run tests still
# has a dev binary, and paying for an optimised link before every trial is what
# makes a one-line change feel like a rebuild of the world.
if [ -n "${FERROX_BIN:-}" ]; then
  BIN="$FERROX_BIN"
elif [ -x "$FERROX_ROOT/ferrox-app" ]; then
  BIN="$FERROX_ROOT/ferrox-app"
elif [ -x "$FERROX_ROOT/target/release/ferrox-app" ]; then
  BIN="$FERROX_ROOT/target/release/ferrox-app"
else
  BIN="$FERROX_ROOT/target/debug/ferrox-app"
fi
# Both live outside this repository: the account, the pass and the exit
# country are the machine's business, never the tree's. Override with
# FOXY_CONF_DIR and FOXY_CREDENTIALS when a shared ~/.config is not wanted.
CONF_DIR="${FOXY_CONF_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/ferrox}"
CREDENTIALS="${FOXY_CREDENTIALS:-$CONF_DIR/credentials}"
CATALOG_URL="https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
LOG="$CONF_DIR/foxy.log"

COUNTRY="${FOXY_COUNTRY:-US}"
CITY="${FOXY_CITY:-}"
CARRIER="${FOXY_CARRIER:-auto}"
MODE="${FOXY_MODE:-all}"
UPSTREAM="${FOXY_UPSTREAM_PROXY:-}"
SOCKS_PORT="${FOXY_SOCKS_PORT:-10808}"
HTTP_PORT="${FOXY_HTTP_PORT:-8080}"
MIXED_PORT="${FOXY_MIXED_PORT:-10809}"
EMAIL="${FOXY_EMAIL:-}"
PASS="${FOXY_PASS:-}"
CODE="${FOXY_CODE:-}"
ACTION="up"
WANT_VPN=0
CLEAR_VPN=0

usage() {
  cat <<EOF
usage: ./foxy-connect.sh <action> [options]

actions
  up                 start the lane and print how to use it (default action)
  down               stop the lane and clear the system proxy this set
  status             show the session, the carriers actually opened, then the exit IP and country
  check              one 1 MB download per method: socks, http front, mixed,
                     and per carrier h1/h2/h3; each asserts 1000000 bytes and
                     the pinned country
  countries          list the exit countries the published catalogue offers

options
  --country CC       exit country, default US (env FOXY_COUNTRY)
  --city CODE        city tier inside the country, default any (env FOXY_CITY)
  --carrier NAME     auto|h1|h2|h3, default auto (env FOXY_CARRIER); auto tries
                     h2, then h1, then h3 and keeps the first that answers. On the
                     CI runner's own egress h2 outran h3 in every run and on every
                     runner, so auto opens on h2; name h3 only when UDP is needed
                     or the edge's TCP is filtered
  --mode MODE        socks|http|mixed|vpn|all, default all: which local fronts
                     to serve; vpn = all fronts plus the system proxy
  --socks PORT       SOCKS5 front port, default 10808
  --http PORT        HTTP CONNECT front port, default 8080
  --mixed PORT       mixed (socks+http, one port) front, default 10809
  --upstream URL     http://host:port or socks5(h)://host:port: chain the edge
                     dial through that proxy (env FOXY_UPSTREAM_PROXY)
  --email ADDR       Firefox account, else FOXY_EMAIL, else the credentials file
  --pass-from-file   read the password from \$FOXY_CREDENTIALS (never echoed)
  --code CODE        two-factor code when the account asks for one
  --build            force a build instead of reusing target/debug/ferrox-app
  -h, --help         this text

credentials file (never committed; created by the first run, mode 0600)
  ${XDG_CONFIG_HOME:-$HOME/.config}/ferrox/credentials, two lines:
  FOXY_EMAIL=... then FOXY_PASS=...
  Rotate the account password after any shared machine has seen it.
EOF
}

die() { echo "foxy-connect: $*" >&2; exit 1; }

# Every front this script can start, so status and down agree on what to stop.
fronts_for() {
  case "$1" in
    socks) printf '%s\n' socks ;;
    http) printf '%s\n' http ;;
    mixed) printf '%s\n' mixed ;;
    all|vpn) printf '%s\n' socks http mixed ;;
    *) die "unknown mode $1" ;;
  esac
}

front_port() {
  case "$1" in
    socks) echo "$SOCKS_PORT" ;;
    http) echo "$HTTP_PORT" ;;
    mixed) echo "$MIXED_PORT" ;;
  esac
}

lane_pid_file() { printf '%s/lane.pid' "$CONF_DIR"; }

lane_meta_file() { printf '%s/lane.meta' "$CONF_DIR"; }

# The launch settings a later status needs. No credential is written here.
write_lane_meta() {
  local meta
  meta="$(lane_meta_file)"
  printf 'mode=%s\nsocks_port=%s\nhttp_port=%s\nmixed_port=%s\ncountry=%s\ncity=%s\ncarrier=%s\nupstream=%s\nbin=%s\n' \
    "$MODE" "$SOCKS_PORT" "$HTTP_PORT" "$MIXED_PORT" "$COUNTRY" "$CITY" "$CARRIER" "$UPSTREAM" "$BIN" >"$meta" ||
    die "could not write $meta; the lane was not started."
  chmod 600 "$meta" 2>/dev/null || true
}

load_lane_meta() {
  local meta field value mode="$MODE" socks_port="$SOCKS_PORT" http_port="$HTTP_PORT"
  local mixed_port="$MIXED_PORT" country="$COUNTRY" city="$CITY" carrier="$CARRIER" upstream="$UPSTREAM"
  local bin="$BIN"
  meta="$(lane_meta_file)"
  [ -r "$meta" ] || return 1
  while IFS='=' read -r field value; do
    case "$field" in
      mode) mode="$value" ;;
      socks_port) socks_port="$value" ;;
      http_port) http_port="$value" ;;
      mixed_port) mixed_port="$value" ;;
      country) country="$value" ;;
      city) city="$value" ;;
      carrier) carrier="$value" ;;
      upstream) upstream="$value" ;;
      bin) bin="$value" ;;
    esac
  done <"$meta"
  case "$mode" in socks|http|mixed|all|vpn) ;; *) return 1 ;; esac
  MODE="$mode" SOCKS_PORT="$socks_port" HTTP_PORT="$http_port" MIXED_PORT="$mixed_port"
  COUNTRY="$country" CITY="$city" CARRIER="$carrier" UPSTREAM="$upstream" BIN="$bin"
}

lane_lock_dir() { printf '%s/lane.lock' "$CONF_DIR"; }

# One start at a time: two calls can both see no lane before either writes the
# pid, and the loser would overwrite the winner's record.
acquire_lane_lock() {
  local lock owner i
  lock="$(lane_lock_dir)"
  for i in 1 2 3 4 5; do
    if mkdir "$lock" 2>/dev/null; then break; fi
    owner="$(cat "$lock/owner" 2>/dev/null || true)"
    if [ -z "$owner" ]; then sleep 0.1; owner="$(cat "$lock/owner" 2>/dev/null || true)"; fi
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
      die "another foxy-connect start is running (pid $owner)."
    fi
    rm -rf "$lock"
  done
  [ -d "$lock" ] || die "could not lock $CONF_DIR; nothing was started."
  printf '%s\n' "$$" >"$lock/owner" || die "could not record the lane lock; nothing was started."
  trap 'rm -rf "$(lane_lock_dir)"' EXIT
}

lane_recorded_bin() {
  local meta key value
  meta="$(lane_meta_file)"
  [ -r "$meta" ] || return 1
  while IFS='=' read -r key value; do
    if [ "$key" = bin ] && [ -n "$value" ]; then printf '%s\n' "$value"; return 0; fi
  done <"$meta"
  return 1
}

lane_pid_matches() {
  local pid="$1" command
  command="$(ps -p "$pid" -ww -o command= 2>/dev/null)" || return 1
  case "$command" in
    *"${BIN##*/}"*"$CONF_DIR"/foxy-*.json*) return 0 ;;
  esac
  return 1
}

lane_running() {
  local pid_file pid
  pid_file="$(lane_pid_file)"
  [ -f "$pid_file" ] || return 1
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

stop_lane() {
  local pid_file pid i rc=0 saved_bin="$BIN" recorded
  recorded="$(lane_recorded_bin || true)"
  [ -n "$recorded" ] && BIN="$recorded"
  pid_file="$(lane_pid_file)"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && ! lane_pid_matches "$pid"; then
      rm -f "$pid_file"
    elif [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for i in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
        for i in $(seq 1 20); do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
      fi
      if kill -0 "$pid" 2>/dev/null; then
        echo "lane pid $pid did not exit after SIGKILL; keeping $pid_file." >&2
        rc=1
      else
        rm -f "$pid_file"
      fi
    else
      rm -f "$pid_file"
    fi
  fi
  if [ "$CLEAR_VPN" = 1 ] || [ -f "$CONF_DIR/system-proxy.ports" ] || [ -f "$CONF_DIR/system-proxy.state" ]; then
    system_proxy_off || rc=$?
  fi
  BIN="$saved_bin"
  return "$rc"
}

proxy_field() {
  printf '%s\n' "$1" | sed -n "s/^$2:[[:space:]]*//p" | head -n 1
}

# One service's prior proxy settings, tab-separated, so down can put back only
# the fields this script changed.
system_proxy_snapshot() {
  local svc="$1" line s_on s_srv s_port w_on w_srv w_port e_on e_srv e_port
  line="$(networksetup -getsocksfirewallproxy "$svc" 2>/dev/null)" || return 1
  s_on="$(proxy_field "$line" Enabled | tr '[:upper:]' '[:lower:]')"
  s_srv="$(proxy_field "$line" Server)"; s_port="$(proxy_field "$line" Port)"
  line="$(networksetup -getwebproxy "$svc" 2>/dev/null)" || return 1
  w_on="$(proxy_field "$line" Enabled | tr '[:upper:]' '[:lower:]')"
  w_srv="$(proxy_field "$line" Server)"; w_port="$(proxy_field "$line" Port)"
  line="$(networksetup -getsecurewebproxy "$svc" 2>/dev/null)" || return 1
  e_on="$(proxy_field "$line" Enabled | tr '[:upper:]' '[:lower:]')"
  e_srv="$(proxy_field "$line" Server)"; e_port="$(proxy_field "$line" Port)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$svc" "${s_on:--}" "${s_srv:--}" "${s_port:--}" \
    "${w_on:--}" "${w_srv:--}" "${w_port:--}" \
    "${e_on:--}" "${e_srv:--}" "${e_port:--}"
}

# Restore one field only while it still points at the port this lane armed.
proxy_restore_kind() {
  local svc="$1" kind="$2" ours="$3" prior_on="$4" prior_srv="$5" prior_port="$6"
  local get set setter line server port
  case "$kind" in
    socks) get=-getsocksfirewallproxy; set=-setsocksfirewallproxystate; setter=-setsocksfirewallproxy ;;
    web) get=-getwebproxy; set=-setwebproxystate; setter=-setwebproxy ;;
    secureweb) get=-getsecurewebproxy; set=-setsecurewebproxystate; setter=-setsecurewebproxy ;;
  esac
  line="$(networksetup "$get" "$svc" 2>/dev/null)" || return 1
  server="$(proxy_field "$line" Server)"
  port="$(proxy_field "$line" Port)"
  case "$server" in 127.*|localhost|::1) ;; *) return 0 ;; esac
  if [ "$port" != "$ours" ]; then
    if [ -n "$prior_srv" ] && [ "$prior_srv" != - ] &&
      [ -n "$prior_port" ] && [ "$prior_port" != - ] &&
      [ "$server" = "$prior_srv" ] && [ "$port" = "$prior_port" ]; then
      if [ "$prior_on" = yes ]; then
        networksetup "$set" "$svc" on 2>/dev/null || return 1
      else
        networksetup "$set" "$svc" off 2>/dev/null || return 1
      fi
    fi
    return 0
  fi
  if [ -n "$prior_srv" ] && [ "$prior_srv" != - ] &&
    [ -n "$prior_port" ] && [ "$prior_port" != - ]; then
    networksetup "$setter" "$svc" "$prior_srv" "$prior_port" 2>/dev/null || return 1
    if [ "$prior_on" = yes ]; then
      networksetup "$set" "$svc" on 2>/dev/null || return 1
    else
      networksetup "$set" "$svc" off 2>/dev/null || return 1
    fi
  else
    networksetup "$set" "$svc" off 2>/dev/null || return 1
  fi
}

# The record holds the ports and every service this lane armed plus its prior
# settings; a failure keeps the record so a later down can retry.
system_proxy_off() {
  local ports_file="$CONF_DIR/system-proxy.ports"
  local state_file="$CONF_DIR/system-proxy.state"
  if [ ! -f "$ports_file" ] && [ ! -f "$state_file" ]; then return 0; fi
  if ! command -v networksetup >/dev/null 2>&1; then
    rm -f "$ports_file" "$state_file"
    return 0
  fi
  local socks="" http="" ports="" failed=0 svc kind get set line enabled server port want
  local s_on s_srv s_port w_on w_srv w_port e_on e_srv e_port
  if [ -r "$ports_file" ]; then
    ports="$(cat "$ports_file")"
    socks="${ports%% *}"; http="${ports##* }"
  fi
  if [ -f "$state_file" ] && [ -z "$ports" ]; then
    echo "system proxy: $state_file has no port record; keeping it for a retry." >&2
    return 1
  fi
  if [ -r "$state_file" ] && [ -s "$state_file" ]; then
    while IFS=$'\t' read -r svc s_on s_srv s_port w_on w_srv w_port e_on e_srv e_port; do
      [ -z "$svc" ] && continue
      case "$svc" in *\**) continue;; esac
      if [ -n "$socks" ] && [ "$socks" != - ]; then
        proxy_restore_kind "$svc" socks "$socks" "$s_on" "$s_srv" "$s_port" ||
          { echo "system proxy: could not restore SOCKS on '$svc'." >&2; failed=1; }
      fi
      if [ -n "$http" ] && [ "$http" != - ]; then
        proxy_restore_kind "$svc" web "$http" "$w_on" "$w_srv" "$w_port" ||
          { echo "system proxy: could not restore Web on '$svc'." >&2; failed=1; }
        proxy_restore_kind "$svc" secureweb "$http" "$e_on" "$e_srv" "$e_port" ||
          { echo "system proxy: could not restore Secure Web on '$svc'." >&2; failed=1; }
      fi
    done < "$state_file"
  else
    while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      case "$svc" in *\**) continue;; esac
      for kind in socks web secureweb; do
        case "$kind" in
          socks) get=-getsocksfirewallproxy; set=-setsocksfirewallproxystate; want="$socks" ;;
          web) get=-getwebproxy; set=-setwebproxystate; want="$http" ;;
          secureweb) get=-getsecurewebproxy; set=-setsecurewebproxystate; want="$http" ;;
        esac
        [ -n "$want" ] && [ "$want" != - ] || continue
        line="$(networksetup "$get" "$svc" 2>/dev/null)" ||
          { echo "system proxy: could not read $kind on '$svc'." >&2; failed=1; continue; }
        enabled="$(proxy_field "$line" Enabled | tr '[:upper:]' '[:lower:]')"
        [ "$enabled" = yes ] || continue
        server="$(proxy_field "$line" Server)"
        port="$(proxy_field "$line" Port)"
        case "$server" in 127.*|localhost|::1) ;; *) continue ;; esac
        [ "$port" = "$want" ] || continue
        networksetup "$set" "$svc" off 2>/dev/null ||
          { echo "system proxy: could not clear $kind on '$svc'." >&2; failed=1; }
      done
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  fi
  if [ "$failed" = 1 ]; then
    echo "system proxy: the clear failed; $ports_file is kept for a retry." >&2
    return 1
  fi
  rm -f "$ports_file" "$state_file"
  echo "system proxy cleared (was SOCKS ${socks:--}, HTTP ${http:--})."
  return 0
}

system_proxy_on() {
  if ! command -v networksetup >/dev/null 2>&1; then
    echo "no networksetup here: the fronts stay local, point your apps at them by hand." >&2
    return 0
  fi
  local ports_file="$CONF_DIR/system-proxy.ports"
  local state_file="$CONF_DIR/system-proxy.state"
  if [ -f "$ports_file" ] || [ -f "$state_file" ]; then
    system_proxy_off || return 1
  fi
  local any=0 svc snapshot
  : > "$state_file"; chmod 600 "$state_file" 2>/dev/null || true
  printf '%s %s\n' "$SOCKS_PORT" "$HTTP_PORT" > "$ports_file"
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    case "$svc" in *\**) continue;; esac
    snapshot="$(system_proxy_snapshot "$svc")" || continue
    if ! printf '%s\n' "$snapshot" >>"$state_file"; then
      system_proxy_off >/dev/null 2>&1 || true
      die "could not record the proxy settings for '$svc'; nothing was left armed."
    fi
    networksetup -setsocksfirewallproxy "$svc" 127.0.0.1 "$SOCKS_PORT" 2>/dev/null || continue
    networksetup -setsocksfirewallproxystate "$svc" on 2>/dev/null || true
    networksetup -setwebproxy "$svc" 127.0.0.1 "$HTTP_PORT" 2>/dev/null || true
    networksetup -setwebproxystate "$svc" on 2>/dev/null || true
    networksetup -setsecurewebproxy "$svc" 127.0.0.1 "$HTTP_PORT" 2>/dev/null || true
    networksetup -setsecurewebproxystate "$svc" on 2>/dev/null || true
    any=1
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  if [ "$any" != 1 ]; then
    system_proxy_off >/dev/null 2>&1 || true
    die "no network service took the proxy"
  fi
  echo "system proxy on: SOCKS 127.0.0.1:$SOCKS_PORT, HTTP(S) 127.0.0.1:$HTTP_PORT"
  echo "scope: apps that honour the system proxy (browsers included). No utun device:"
  echo "README rows 29/58, slice P46."
}

front_trace() {
  local front="$1" port="$2"
  local -a via=(-fsSL --max-time 30 --noproxy '')
  if [ "$front" = http ]; then
    via+=(-x "http://127.0.0.1:$port")
  else
    via+=(--socks5-hostname "127.0.0.1:$port")
  fi
  curl "${via[@]}" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true
}

exit_country() {
  local first
  first="$(fronts_for "$MODE" | head -n 1)"
  front_trace "$first" "$(front_port "$first")" | grep -E '^(loc|ip)=' || true
}

# The rung each flow kind last opened, from the lane's own log. `auto` chooses per
# kind (TCP, UDP, CONNECT-IP), so status names each one instead of guessing.
carrier_selected() {
  local kind line
  [ -r "$LOG" ] || return 0
  for kind in tcp udp ip; do
    line="$(grep -F "foxy: carrier $kind " "$LOG" 2>/dev/null | tail -n 1 || true)"
    [ -n "$line" ] && printf '%s %s\n' "$kind" "${line##* }"
  done
  return 0
}

# One flow through the first front, and the pinned country is the assertion: the
# machine's own exit answers the same trace, so any answer is not proof of a lane.
prove_flow() {
  local answer loc
  answer="$(exit_country)"
  loc="$(printf '%s\n' "$answer" | sed -n 's/^loc=//p' | tr '[:lower:]' '[:upper:]')"
  if [ -z "$loc" ]; then
    echo "NOT CONNECTED: the fronts listen, but no flow got through them. Tail $LOG." >&2
    return 1
  fi
  if [ "$loc" != "$COUNTRY" ]; then
    echo "the exit reads $loc, not the pinned $COUNTRY: $(printf '%s\n' "$answer" | tr '\n' ' ')" >&2
    echo "either another edge answers or this machine went direct; tail $LOG." >&2
    return 1
  fi
  echo "exit through the first front: $(printf '%s\n' "$answer" | tr '\n' ' ')"
  return 0
}

wait_port() {
  local port="$1" i
  for i in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      return 0
    fi
    # A lane that died at sign-in will never open the port: name it now, not in a minute.
    lane_running || return 1
    sleep 1
  done
  return 1
}

# 1 MB off the same host the CI legs use, over one of the local fronts.
download_1mb() {
  local front="$1" carrier="$2" want="$3"
  local port out got loc
  port="$(front_port "$front")"
  out="$CONF_DIR/check-$front-$carrier.bin"
  local -a curl_args=(-sS --max-time 300 --noproxy '')
  if [ "$front" = http ]; then
    curl_args+=(-x "http://127.0.0.1:$port")
  else
    curl_args+=(--socks5-hostname "127.0.0.1:$port")
  fi
  if curl "${curl_args[@]}" 'https://speed.cloudflare.com/__down?bytes=1000000' -o "$out"; then
    got="$(wc -c < "$out" | tr -d ' ')"
    if [ "$got" = 1000000 ]; then
      loc="$(front_trace "$front" "$port" | sed -n 's/^loc=//p' | tr '[:lower:]' '[:upper:]')"
      if [ "$loc" = "$want" ]; then
        echo "ok   $front over $carrier: 1000000 B from $loc"
        return 0
      fi
      rm -f "$out"
      echo "FAIL $front over $carrier: exit reads ${loc:-unknown}, wanted $want" >&2
      return 1
    fi
  fi
  rm -f "$out"
  echo "FAIL $front over $carrier: got ${got:-0} bytes, exit $(exit_country | grep '^loc=' || echo unknown)" >&2
  return 1
}

write_config() {
  local cfg="$1"; shift
  FERR_EMAIL="$EMAIL" FERR_PASS="$PASS" FERR_CODE="$CODE" FERR_UPSTREAM="$UPSTREAM" \
    python3 - "$cfg" "$COUNTRY" "$CITY" "$CARRIER" "$SOCKS_PORT" "$HTTP_PORT" "$MIXED_PORT" "$MODE" <<'PY'
import json, os, sys
cfg, country, city, carrier, socks, http, mixed, mode = sys.argv[1:9]
email = os.environ["FERR_EMAIL"]
password = os.environ["FERR_PASS"]
code = os.environ["FERR_CODE"]
upstream = os.environ["FERR_UPSTREAM"]
settings = {"email": email, "password": password, "country": country, "carrier": carrier}
if code:
    settings["code"] = code
if city:
    settings["city"] = city
if upstream:
    settings["upstreamProxy"] = upstream
fronts = {"socks": ["socks"], "http": ["http"], "mixed": ["mixed"]}.get(mode, ["socks", "http", "mixed"])
ports = {"socks": int(socks), "http": int(http), "mixed": int(mixed)}
doc = {
    "inbounds": [{"protocol": p, "listen": "127.0.0.1", "port": ports[p]} for p in fronts],
    "outbounds": [{"protocol": "foxy", "settings": settings}],
}
with open(cfg, "w") as f:
    json.dump(doc, f, indent=2)
PY
  chmod 600 "$cfg"
}

list_countries() {
  curl -fsSL --max-time 25 "$CATALOG_URL" | python3 -c '
import json,sys
body=json.load(sys.stdin)
seen={}
for r in body.get("data",[]):
    c=r.get("country",r)
    code=(c.get("code") or "").upper()
    name=c.get("name") or ""
    if len(code)==2 and code not in seen:
        seen[code]=name
for code in sorted(seen):
    mark="  <- default" if code=="US" else ""
    print(f"{code}  {seen[code]}{mark}")
'
}

ACTION="up"
while [ $# -gt 0 ]; do
  case "$1" in
    up|down|status|check|countries) ACTION="$1"; shift;;
    --country) COUNTRY="${2:-}"; shift 2;;
    --city) CITY="${2:-}"; shift 2;;
    --carrier) CARRIER="${2:-}"; shift 2;;
    --mode) MODE="${2:-}"; shift 2;;
    --socks) SOCKS_PORT="${2:-}"; shift 2;;
    --http) HTTP_PORT="${2:-}"; shift 2;;
    --mixed) MIXED_PORT="${2:-}"; shift 2;;
    --upstream) UPSTREAM="${2:-}"; shift 2;;
    --email) EMAIL="${2:-}"; shift 2;;
    --pass-from-file) shift;;
    --code) CODE="${2:-}"; shift 2;;
    --vpn) MODE="vpn"; shift;;
    --no-vpn) CLEAR_VPN=1; shift;;
    --tun) die "--tun is refused: this binary has no TUN inbound and no tun2socks engine (README rows 29 and 58, slice P46). Use --mode vpn for the system proxy, or --mode socks|http|mixed for one app." ;;
    --build) FORCE_BUILD=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1 (see --help)";;
  esac
done

mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"

if [ "$ACTION" = countries ]; then list_countries; exit 0; fi
if [ "$ACTION" = down ]; then
  CLEAR_VPN=1
  if ! stop_lane; then
    echo "the lane stopped, but the system proxy could not be cleared; its record is kept; run down again." >&2
    exit 1
  fi
  # The lane configs carry the account password, so they go when the lane does.
  rm -f "$CONF_DIR"/foxy-*.json "$(lane_meta_file)"
  echo "lane stopped; configs under $CONF_DIR removed."
  exit 0
fi
if [ "$ACTION" = status ]; then
  if ! lane_running; then
    echo "lane not running (pid file $(lane_pid_file) absent)."
    exit 1
  fi
  load_lane_meta || echo "foxy-connect: lane metadata missing; showing the current environment." >&2
  echo "lane running (pid $(cat "$(lane_pid_file)")), fronts:"
  for front in $(fronts_for "$MODE"); do
    case "$front" in
      http) echo "  HTTP CONNECT  http://127.0.0.1:$HTTP_PORT   (curl -x, browsers' HTTP proxy)" ;;
      socks) echo "  SOCKS5        socks5://127.0.0.1:$SOCKS_PORT (curl --socks5-hostname, UDP-aware)" ;;
      mixed) echo "  mixed         http://127.0.0.1:$MIXED_PORT   (socks and http on one port)" ;;
    esac
  done
  selection="$(carrier_selected | awk '{printf "%s%s %s", sep, $1, $2; sep=", "}')"
  echo "exit country: $COUNTRY, carrier: $CARRIER (${selection:-not selected yet})${UPSTREAM:+, upstream $UPSTREAM}"
  echo "log:  $LOG   stop: ./foxy-connect.sh down"
  exit_country
  exit 0
fi

# Everything after this point needs a lane, so the binary and the pass first.
if [ "${FORCE_BUILD:-0}" = 1 ] || [ ! -x "$BIN" ]; then
  [ -f "$FERROX_ROOT/Cargo.toml" ] || die "no binary at $BIN and no source tree to build one"
  # The release profile optimises every dependency and links with thin LTO: a
  # cold build is many minutes and an app edit is minutes more. The dev profile
  # reuses the test cycle's warm dependencies and finishes in seconds.
  if [ "${FERROX_PROFILE:-debug}" = release ] || [ "${FERROX_RELEASE:-0}" = 1 ]; then
    echo "building ferrox-app (release; minutes, not seconds)..."
    (cd "$FERROX_ROOT" && cargo build --locked --release --target-dir "$FERROX_ROOT/target" -p ferrox-app) >&2
    BIN="$FERROX_ROOT/target/release/ferrox-app"
  else
    echo "building ferrox-app (dev profile; seconds)..."
    (cd "$FERROX_ROOT" && cargo build --locked --target-dir "$FERROX_ROOT/target" -p ferrox-app) >&2
    BIN="$FERROX_ROOT/target/debug/ferrox-app"
  fi
fi

if [ -n "$CREDENTIALS" ] && [ -f "$CREDENTIALS" ]; then
  # A credentials file inside this repository is a secret someone is about to
  # commit: it is refused rather than read, however it is spelled or tracked.
  if command -v python3 >/dev/null 2>&1; then
    cred_real="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$CREDENTIALS")"
    root_real="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$FERROX_ROOT")"
  else
    cred_real="$CREDENTIALS"
    root_real="$(cd "$FERROX_ROOT" && pwd -P)"
  fi
  case "$cred_real" in
    "$root_real"/*)
      die "$CREDENTIALS resolves inside the repository; move it to $HOME/.ferrox/credentials (0600)" ;;
  esac
  explicit_email="$EMAIL"; explicit_pass="$PASS"
  # shellcheck disable=SC1090
  . "$CREDENTIALS"
  EMAIL="${explicit_email:-${FOXY_EMAIL:-$EMAIL}}"
  PASS="${explicit_pass:-${FOXY_PASS:-$PASS}}"
fi
if [ -n "$EMAIL" ] && [ -z "$PASS" ] && [ -t 0 ]; then
  printf 'Firefox password for %s: ' "$EMAIL" >&2
  stty -echo 2>/dev/null || true
  read -r PASS || true
  stty echo 2>/dev/null || true
  printf '\n' >&2
fi
[ -n "$EMAIL" ] || die "no account: put FOXY_EMAIL/FOXY_PASS in $CREDENTIALS (0600, outside git) or pass --email"
[ -n "$PASS" ] || die "no password: $CREDENTIALS or FOXY_PASS"

case "$MODE" in socks|http|mixed|all|vpn) ;; *) die "unknown mode $MODE (socks, http, mixed, vpn, all)";; esac
CITY="$(printf '%s' "$CITY" | tr '[:lower:]' '[:upper:]')"
case "$CARRIER" in auto|h1|h2|h3|http/1.1|http/2|quic) ;; *) CARRIER="auto";; esac

acquire_lane_lock
if lane_running; then stop_lane || die "the system proxy could not be cleared; fix it before starting another lane."; fi
CFG="$CONF_DIR/foxy-$COUNTRY.json"
write_config "$CFG"
write_lane_meta
echo "config: $CFG (mode 0600, under $CONF_DIR)"
"$BIN" run -c "$CFG" >"$LOG" 2>&1 &
echo "$!" > "$(lane_pid_file)"

FRONTS="$(fronts_for "$MODE" | tr '\n' ' ')"
for front in $FRONTS; do
  port="$(front_port "$front")"
  wait_port "$port" || { echo "lane died; tail $LOG:" >&2; tail -n 30 "$LOG" >&2; exit 1; }
done
echo "lane up (pid $(cat "$(lane_pid_file)")), fronts:"
for front in $FRONTS; do
  case "$front" in
    http) echo "  HTTP CONNECT  http://127.0.0.1:$HTTP_PORT   (curl -x, browsers' HTTP proxy)" ;;
    socks) echo "  SOCKS5        socks5://127.0.0.1:$SOCKS_PORT (curl --socks5-hostname, UDP-aware)" ;;
    mixed) echo "  mixed         http://127.0.0.1:$MIXED_PORT   (socks and http on one port)" ;;
  esac
done
echo "exit country: $COUNTRY, carrier: $CARRIER${UPSTREAM:+, upstream $UPSTREAM}"
echo "curl: curl --socks5-hostname 127.0.0.1:$SOCKS_PORT https://api.ipify.org"
echo "log:  $LOG   stop: ./foxy-connect.sh down"

if [ "$ACTION" = check ]; then
  first="$(fronts_for "$MODE" | head -n 1)"
  port="$(front_port "$first")"
  for i in $(seq 1 24); do
    exit_country | grep -qx "loc=$COUNTRY" && break
    sleep 5
  done
  local_country="$(exit_country | sed -n 's/^loc=//p')"
  if [ "$local_country" != "$COUNTRY" ]; then
    echo "exit country is ${local_country:-unreadable}, wanted $COUNTRY; see $LOG" >&2
    exit 1
  fi
  # One 1 MB download per method the fronts offer, so each front is proven
  # separately and not through the one that answered first.
  for front in $(fronts_for "$MODE"); do
    download_1mb "$front" "$CARRIER" "$COUNTRY" || DOWN_FAILED=1
  done
  # Each carrier proves the lane itself: auto is a start, so each explicit
  # carrier gets its own lane start. The last test leaves a SOCKS-only lane, so
  # put the mode and fronts this check found back before returning.
  if [ "$CARRIER" = auto ]; then
    check_mode="$MODE"
    for carrier in h1 h2 h3; do
      stop_lane
      MODE="socks"
      CARRIER="$carrier"
      CFG="$CONF_DIR/foxy-$COUNTRY-$carrier.json"
      write_config "$CFG"
      write_lane_meta
      "$BIN" run -c "$CFG" >"$LOG" 2>&1 &
      echo "$!" > "$(lane_pid_file)"
      wait_port "$SOCKS_PORT" || { echo "carrier $carrier never listened" >&2; DOWN_FAILED=1; continue; }
      download_1mb socks "$carrier" "$COUNTRY" || DOWN_FAILED=1
    done
    stop_lane
    MODE="$check_mode"
    CARRIER="auto"
    CFG="$CONF_DIR/foxy-$COUNTRY.json"
    write_config "$CFG"
    write_lane_meta
    FRONTS="$(fronts_for "$MODE" | tr '\n' ' ')"
    "$BIN" run -c "$CFG" >"$LOG" 2>&1 &
    echo "$!" > "$(lane_pid_file)"
    for front in $FRONTS; do
      port="$(front_port "$front")"
      wait_port "$port" || { echo "the original fronts did not reopen" >&2; DOWN_FAILED=1; break; }
    done
    if [ "$MODE" = vpn ] && [ "${DOWN_FAILED:-0}" != 1 ]; then
      prove_flow && system_proxy_on || DOWN_FAILED=1
    fi
  fi
  if [ "${DOWN_FAILED:-0}" = 1 ]; then
    echo "check failed; see $LOG" >&2
    exit 1
  fi
  echo "check passed: $COUNTRY exit, 1000000 B per method."
  exit 0
fi

# Point the machine at the lane only after one flow came through it: an armed
# system proxy over a lane that carries nothing takes the network down with it.
if [ "$MODE" = vpn ]; then
  prove_flow || { echo "the lane stays up so it can be inspected; the system proxy is untouched." >&2; exit 3; }
  system_proxy_on
  echo "browsers may need a restart to pick the new proxy up."
else
  prove_flow || exit 3
fi
