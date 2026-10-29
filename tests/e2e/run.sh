#!/usr/bin/env bash
# End-to-end tests for the p2p host.
#
# These are opt-in and local: they build the real gost + p2p binaries, run a
# real derper, and drive traffic through real namespaces. They are NOT a CI
# gate -- hole punching and STUN are timing/NAT dependent -- and they are not
# run by `go test ./...` (see e2e_test.go for the gated wrapper).
#
#   ./tests/e2e/run.sh                 # all scenarios
#   ./tests/e2e/run.sh --list
#   ./tests/e2e/run.sh --scenario stub
#   ./tests/e2e/run.sh --keep          # keep logs/binaries for debugging
#
# Prerequisites: Linux with CAP_NET_ADMIN (root, or uid in a userns), Docker
# (to extract the derper binary), openssl, curl, ping. See README.md.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
P2P_DIR=$(cd "$HERE/../.." && pwd)
REPO_DIR=$(cd "$P2P_DIR/.." && pwd)
GOST_DIR="$REPO_DIR/gost"

# shellcheck source=lib.sh
. "$HERE/lib.sh"

WORK="${P2P_E2E_WORK:-/tmp/p2p-e2e}"
# Include $RANDOM so a reused PID across invocations cannot collide on a run
# directory (stale logs would otherwise satisfy wait_log immediately).
RUN_ID=$(date +%Y%m%d-%H%M%S)-$$-$RANDOM
RUNDIR="$WORK/runs/$RUN_ID"
LOGDIR="$RUNDIR/logs"
mkdir -p "$RUNDIR/pids" "$LOGDIR"

KEEP=0
SKIP_BUILD=0
ONLY=""
GOST_BIN="${GOST_BIN:-}"
P2P_BIN="${P2P_BIN:-}"
HELPER_BIN="${HELPER_BIN:-}"
DERPER_BIN="${DERPER_BIN:-}"

# Scenario registry: --list, --scenario validation and the runner all read this
# single list, so a new scenario just needs an entry here and a scenario_<name>
# function below.
SCENARIOS=(stub derp-relay relay-peer-restart derp-direct quic-direct forward inner-matrix udp-tun udp-tun-loss udp-outlet ipv6-direct oneway-direct)

usage() {
	sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

die_usage() { echo "$1" >&2; usage; exit 2; }

# need_arg <option> [args...]: every flag that takes a value calls this first so
# a missing value prints usage instead of tripping `set -u`.
need_arg() { [ $# -ge 2 ] || die_usage "$1 needs a value"; }

scenario_known() {
	local s
	for s in "${SCENARIOS[@]}"; do [ "$s" = "$1" ] && return 0; done
	return 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--list)
		say "scenarios: ${SCENARIOS[*]}"
		exit 0
		;;
	--scenario)
		need_arg "$@"
		scenario_known "$2" || die_usage "unknown scenario: $2"
		ONLY=$2; shift 2 ;;
	--work)
		need_arg "$@"
		WORK=$2; RUNDIR="$WORK/runs/$RUN_ID"; LOGDIR="$RUNDIR/logs"; mkdir -p "$RUNDIR/pids" "$LOGDIR"; shift 2 ;;
	--keep) KEEP=1; shift ;;
	--skip-build) SKIP_BUILD=1; shift ;;
	--gost-bin) need_arg "$@"; GOST_BIN=$2; shift 2 ;;
	--p2p-bin) need_arg "$@"; P2P_BIN=$2; shift 2 ;;
	--derper-bin) need_arg "$@"; DERPER_BIN=$2; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) die_usage "unknown argument: $1" ;;
	esac
done

# Armed only after argument parsing, so --list/--help do not run teardown.
trap cleanup_all EXIT

# --- toolchain ---------------------------------------------------------------

find_go() {
	if command -v go >/dev/null 2>&1; then
		command -v go
		return
	fi
	local c
	for c in "$HOME/.local/go/bin/go" /usr/local/go/bin/go /usr/lib/go/bin/go; do
		[ -x "$c" ] && { echo "$c"; return; }
	done
	return 1
}

GO=$(find_go) || { echo "go toolchain not found" >&2; exit 1; }

build_binaries() {
	[ -z "$P2P_BIN" ] && P2P_BIN="$WORK/bin/p2p"
	[ -z "$HELPER_BIN" ] && HELPER_BIN="$WORK/bin/helper"
	[ -z "$GOST_BIN" ] && GOST_BIN="$WORK/bin/gost"
	if [ "$SKIP_BUILD" = 1 ]; then
		local b
		for b in "$P2P_BIN" "$HELPER_BIN" "$GOST_BIN"; do
			[ -x "$b" ] || { echo "--skip-build but missing $b" >&2; exit 1; }
		done
		return 0
	fi
	mkdir -p "$WORK/bin"
	say "building p2p..."
	(cd "$P2P_DIR" && "$GO" build -o "$P2P_BIN" ./cmd/p2p) || { echo "p2p build failed" >&2; exit 1; }
	say "building helper..."
	(cd "$P2P_DIR" && "$GO" build -o "$HELPER_BIN" ./tests/e2e/helper) || { echo "helper build failed" >&2; exit 1; }
	say "building gost..."
	(cd "$GOST_DIR" && CGO_ENABLED=0 "$GO" build -o "$GOST_BIN" ./cmd/gost) || { echo "gost build failed" >&2; exit 1; }
}

extract_derper() {
	[ -n "$DERPER_BIN" ] && { [ -x "$DERPER_BIN" ] && return 0 || { echo "DERPER_BIN not executable: $DERPER_BIN" >&2; exit 1; }; }
	local cached="$WORK/derper-root/usr/local/bin/derper"
	if [ -x "$cached" ]; then
		DERPER_BIN=$cached
		return 0
	fi
	command -v docker >/dev/null 2>&1 || { echo "docker required to extract derper (or pass --derper-bin)" >&2; exit 1; }
	say "extracting derper from ${DERPER_IMAGE:-gogost/derper}..."
	mkdir -p "$WORK/derper-root"
	docker create --name "p2p-e2e-derper-$$" "${DERPER_IMAGE:-gogost/derper}" >/dev/null || { echo "docker create failed" >&2; exit 1; }
	docker export "p2p-e2e-derper-$$" | tar -C "$WORK/derper-root" -xf -
	docker rm "p2p-e2e-derper-$$" >/dev/null
	[ -x "$cached" ] || { echo "derper not found in image (looked for $cached)" >&2; exit 1; }
	DERPER_BIN=$cached
}

# --- shared fixtures ---------------------------------------------------------

# gen_cert <dir> <host>: self-signed cert/key named <host>.crt/.key, which is
# what derper's manual cert mode expects.
gen_cert() {
	local dir=$1 host=$2 san
	command -v openssl >/dev/null 2>&1 || { echo "openssl required to generate certs" >&2; return 1; }
	mkdir -p "$dir"
	if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then san="IP:$host"; else san="DNS:$host"; fi
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "$dir/$host.key" -out "$dir/$host.crt" -days 3 \
		-subj "/CN=$host" -addext "subjectAltName=$san" >/dev/null 2>&1 || return 1
}

setup_net() {
	ns_probe_mode
	net_teardown
	net_bridge_up
	ns_add A
	ns_add B
	net_host_up A "$HOST_A_IP"
	net_host_up B "$HOST_B_IP"
	say "namespaces A=$HOST_A_IP B=$HOST_B_IP (mode=$NS_MODE), bridge $BRIDGE"
}

# start_derper <logname> <on|off>
start_derper() {
	local name=$1 stun=${2:-on}
	local dir="$RUNDIR/derper-$name"
	gen_cert "$dir/certs" "$DERP_IP" || { fail "derper cert generation failed"; return 1; }
	local args=(-c "$dir/derper.json" -hostname "$DERP_IP" -certmode manual
		-certdir "$dir/certs" -a "$DERP_IP:443" -http-port -1)
	[ "$stun" = off ] && args+=(-stun=false)
	bg "$name" "$DERPER_BIN" "${args[@]}"
	wait_tcp - "$DERP_IP" 443 25 || { fail "derper $name did not listen on 443"; return 1; }
	ok "derper $name up (stun=$stun)"
}

# start_p2p <ns> <logname> <args...>
start_p2p() {
	local ns=$1 name=$2
	shift 2
	ns_bg "$ns" "$name" "$P2P_BIN" "$@" --log.level debug --log.format json
}

start_gost() { # <ns> <logname> <args...>
	local ns=$1 name=$2
	shift 2
	ns_bg "$ns" "$name" "$GOST_BIN" "$@"
}

# p2p_pubkey <logname>: extract the base64 public key the host prints at startup.
p2p_pubkey() {
	local f="$LOGDIR/$1.log" i
	for i in $(seq 1 100); do
		local k
		k=$(grep -oE '"pubkey":"[^"]+"' "$f" 2>/dev/null | head -1 | sed 's/.*:"//;s/"$//')
		[ -n "$k" ] && { echo "$k"; return 0; }
		sleep 0.1
	done
	return 1
}

wait_status_ge() { # <ns> <addr> <field> <min> [timeout] [token]
	local ns=$1 addr=$2 field=$3 min=$4 t=${5:-30} token=${6:-}
	local i out v
	for i in $(seq 1 $((t * 2))); do
		out=$(ns_run "$ns" "$HELPER_BIN" status "$addr" $token 2>/dev/null) || true
		v=$(printf '%s' "$out" | sed -n "s/.*\"$field\":\([0-9-]*\).*/\1/p")
		if [ -n "$v" ] && [ "$v" -ge "$min" ] 2>/dev/null; then return 0; fi
		sleep 0.5
	done
	return 1
}

status_json() { # <ns> <addr> [token]
	ns_run "$1" "$HELPER_BIN" status "$2" ${3:-} 2>/dev/null || true
}

# save_status <ns> <addr> <file> [token]: write the StatusReply JSON to a file
# so assertions can grep it.
save_status() {
	status_json "$1" "$2" "${4:-}" >"$3"
}

# wait_status_eq <ns> <addr> <field> <value> [timeout] [token]
wait_status_eq() {
	local ns=$1 addr=$2 field=$3 want=$4 t=${5:-15} token=${6:-}
	local i out v
	for i in $(seq 1 $((t * 2))); do
		out=$(ns_run "$ns" "$HELPER_BIN" status "$addr" $token 2>/dev/null) || true
		v=$(printf '%s' "$out" | sed -n "s/.*\"$field\":\([0-9-]*\).*/\1/p")
		if [ -n "$v" ] && [ "$v" = "$want" ]; then return 0; fi
		sleep 0.5
	done
	return 1
}

# gost_client_cfg <file> <plugin-addr> <peer> <dialer> <token> [listen]
# A client proxy whose only chain node is reached through the p2p tunnel.
gost_client_cfg() {
	local file=$1 addr=$2 peer=$3 dialer=$4 token=$5 listen=${6:-127.0.0.1:8080}
	{
		echo "p2ps:"
		echo "  - name: p2p-1"
		echo "    plugin:"
		echo "      type: grpc"
		echo "      addr: $addr"
		[ -n "$token" ] && echo "      token: $token"
		echo "services:"
		echo "  - name: service-0"
		echo "    addr: $listen"
		echo "    handler: {type: auto, chain: chain-0}"
		echo "    listener: {type: tcp}"
		echo "chains:"
		echo "  - name: chain-0"
		echo "    hops:"
		echo "      - name: hop-0"
		echo "        nodes:"
		echo "          - name: node-0"
		echo "            addr: $peer"
		echo "            connector: {type: http}"
		echo "            dialer: {type: $dialer}"
		echo "            metadata: {p2p: p2p-1}"
		echo "log: {level: debug}"
	} >"$file"
}

# start_echo <ns> <name> <addr>: HTTP echo server (hello-p2p + /bulk).
start_echo() {
	ns_bg "$1" "$2" "$HELPER_BIN" http "$3"
}

# start_peer_gost <ns> <logname> <proto> [listen]: a plain gost proxy the
# tunnel's inner dialer speaks to. proto is a gost listener scheme.
start_peer_gost() {
	local ns=$1 name=$2 proto=$3 listen=${4:-127.0.0.1:18080}
	local dir="$RUNDIR/peer-$name"
	local cert=""
	case "$proto" in
	tls | mtls | mws)
		gen_cert "$dir/certs" peer.p2p || fail "peer $proto cert generation failed"
		cert="?cert=$dir/certs/peer.p2p.crt&key=$dir/certs/peer.p2p.key"
		;;
	esac
	ns_bg "$ns" "$name" "$GOST_BIN" -L "$proto://$listen$cert"
}

# --- scenarios ---------------------------------------------------------------

scenario_stub() {
	step "stub: loopback bridge + token auth"
	local dir="$RUNDIR/stub"
	mkdir -p "$dir"

	start_echo - echo 127.0.0.1:18081 # loopback target (stub needs no bridge)
	start_peer_gost - peer http 127.0.0.1:18080
	bg p2p "$P2P_BIN" --addr 127.0.0.1:8003 --log.level debug --log.format json
	wait_tcp - 127.0.0.1 8003 15 || fail "stub host did not listen"

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 127.0.0.1:18080 tcp "" 127.0.0.1:8080
	bg client "$GOST_BIN" -C "$dir/client.yaml"
	wait_tcp - 127.0.0.1 8080 15 || fail "client proxy did not listen"

	local body
	body=$(curl_proxy - http://127.0.0.1:8080 http://127.0.0.1:18081/)
	check "stub tcp tunnel carries HTTP" test "$body" = "hello-p2p"
	local n
	n=$(curl_proxy - http://127.0.0.1:8080 http://127.0.0.1:18081/bulk | wc -c)
	check "stub bulk transfer is 1 MiB" test "$n" -eq 1048576

	# Token: the host enforces it, so a tokenless client must fail and a
	# matching client must work. Swap only the host (keep peer + echo).
	local hp cp
	hp=$(cat "$RUNDIR/pids/p2p" 2>/dev/null || true)
	cp=$(cat "$RUNDIR/pids/client" 2>/dev/null || true)
	[ -n "$hp" ] && kill_pid "$hp"
	[ -n "$cp" ] && kill_pid "$cp"
	bg p2p-tok "$P2P_BIN" --addr 127.0.0.1:8003 --token s3cr3t --log.level debug --log.format json
	wait_tcp - 127.0.0.1 8003 15 || fail "token host did not listen"
	gost_client_cfg "$dir/client-tok.yaml" 127.0.0.1:8003 127.0.0.1:18080 tcp s3cr3t 127.0.0.1:8080
	bg client-tok "$GOST_BIN" -C "$dir/client-tok.yaml"
	wait_tcp - 127.0.0.1 8080 15 || fail "token client did not listen"
	body=$(curl_proxy - http://127.0.0.1:8080 http://127.0.0.1:18081/)
	check "stub with matching token works" test "$body" = "hello-p2p"

	gost_client_cfg "$dir/client-notok.yaml" 127.0.0.1:8003 127.0.0.1:18080 tcp "" 127.0.0.1:8081
	bg client-notok "$GOST_BIN" -C "$dir/client-notok.yaml"
	wait_tcp - 127.0.0.1 8081 15 || fail "tokenless client did not listen"
	body=$(curl_proxy - http://127.0.0.1:8081 http://127.0.0.1:18081/)
	check "stub without token carries no body" test -z "$body"
	# An empty body alone could be any failure. Require the auth rejection that
	# proves the host -- not a transport mishap -- refused the tunnel. The client
	# logs the plugin error: "code = Unauthenticated desc = invalid token".
	check_grep "stub without token is rejected by the host" \
		'Unauthenticated.*invalid token' "$LOGDIR/client-notok.log"

	# p2p's own -C config: a config value must behave like the equivalent flag.
	cat >"$dir/p2p.yaml" <<YAML
addr: 127.0.0.1:8004
token: cfgtok
log: {level: debug, format: json}
YAML
	bg p2p-cfg "$P2P_BIN" -C "$dir/p2p.yaml"
	wait_tcp - 127.0.0.1 8004 15 || fail "config host did not listen"
	gost_client_cfg "$dir/client-cfg.yaml" 127.0.0.1:8004 127.0.0.1:18080 tcp cfgtok 127.0.0.1:8082
	bg client-cfg "$GOST_BIN" -C "$dir/client-cfg.yaml"
	wait_tcp - 127.0.0.1 8082 15 || fail "config client did not listen"
	body=$(curl_proxy - http://127.0.0.1:8082 http://127.0.0.1:18081/)
	check "stub via p2p -C config works" test "$body" = "hello-p2p"
	scenario_cleanup
}

# shared DERP topology: A=client side, B=service side (peer gost + target).
# start_derp_pair <tag> <stun:on|off> <direct:true|false> <b-target> [ipv6] [transport]
start_derp_pair() {
	local tag=$1 stun=$2 direct=$3 btarget=$4 ipv6=${5:-} transport=${6:-}
	local dir="$RUNDIR/$tag"
	mkdir -p "$dir/keys"
	start_derper "$tag" "$stun" || return 1
	# B: bridges inbound tunnels to the peer gost (or holds a udp target).
	local bargs=(--addr 127.0.0.1:8003 --derp "wss://$DERP_IP:443/derp"
		--key "$dir/keys/b" --tls.secure=false)
	[ -n "$btarget" ] && bargs+=(--target "$btarget")
	[ "$direct" = false ] && bargs+=(--direct=false)
	[ "$stun" = on ] && bargs+=(--stun "$DERP_IP:3478")
	if [ "$ipv6" = true ]; then
		bargs+=(--ipv6)
	fi
	[ -n "$transport" ] && bargs+=(--transport "$transport")
	start_p2p B "p2p-$tag-b" "${bargs[@]}"
	# A: client side control plane.
	local aargs=(--addr 127.0.0.1:8003 --derp "wss://$DERP_IP:443/derp"
		--key "$dir/keys/a" --tls.secure=false)
	[ "$direct" = false ] && aargs+=(--direct=false)
	[ "$stun" = on ] && aargs+=(--stun "$DERP_IP:3478")
	if [ "$ipv6" = true ]; then
		aargs+=(--ipv6)
	fi
	[ -n "$transport" ] && aargs+=(--transport "$transport")
	start_p2p A "p2p-$tag-a" "${aargs[@]}"
	p2p_pubkey "p2p-$tag-a" >"$dir/a.pub" || { fail "no A pubkey"; return 1; }
	p2p_pubkey "p2p-$tag-b" >"$dir/b.pub" || { fail "no B pubkey"; return 1; }
	ok "derp pair up ($tag): A=$(cat "$dir/a.pub") B=$(cat "$dir/b.pub")"
}

scenario_derp_relay() {
	step "derp relay-only: two hosts, real derper, no direct path"
	local dir="$RUNDIR/relay"
	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	start_derp_pair relay off false 127.0.0.1:18080 || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"

	local body
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "relay tunnel carries HTTP" test "$body" = "hello-p2p"
	local n
	n=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/bulk" | wc -c)
	check "relay bulk transfer is 1 MiB" test "$n" -eq 1048576

	wait_status_ge A 127.0.0.1:8003 derp_peers 1 20
	save_status A 127.0.0.1:8003 "$dir/status.json"
	check_grep "relay path is used" '"derp_peers":1' "$dir/status.json"
	check_not_grep "no direct session in relay-only mode" '"direct_peers":[1-9]' "$dir/status.json"
	check_grep "status carries a per-peer diagnostic" '"peer_diagnostics":\[' "$dir/status.json"
	check_grep "the diagnostic is keyed by the peer" '"peer":"' "$dir/status.json"
	check_grep "the diagnostic names the transport" '"path":"[a-z-]+"' "$dir/status.json"
	# A non-mux tunnel must leave no residue once the request finishes.
	if wait_status_eq A 127.0.0.1:8003 tunnels 0 15; then
		ok "tunnel record reclaimed after the stream ends (zero residue)"
	else
		save_status A 127.0.0.1:8003 "$dir/status-after.json"
		fail "tunnel count did not return to zero: $(cat "$dir/status-after.json")"
	fi
}

# A peer that restarts — or moves networks — is noticed by smux's own keepalive
# alone: the relay's PeerGone is best-effort (derper sends it to mesh watchers,
# not to open-relay clients) and a session whose far end vanished is served as
# live until that timeout fires, so the tunnel carries nothing meanwhile. This
# guards the pair the timeout is made of: 3s/15s notices a restart well inside
# one timeout, where the old 10s/30s took its whole timeout plus the rebuild
# (measured on a phone: 33s).
scenario_relay_peer_restart() {
	step "derp relay: a restarted peer is noticed within one keepalive timeout"
	local dir="$RUNDIR/restart"
	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	# An open relay, the way the public one runs: a derper that verifies its
	# clients treats them as one mesh and tells the survivors when a peer
	# leaves, which would hide exactly the case here — a session whose far end
	# vanished with nobody to say so. The key is the derper's own node
	# identity, and the file replaces the one it would write for itself.
	mkdir -p "$RUNDIR/derper-restart"
	printf '{"PrivateKey": "privkey:%s", "VerifyClients": false}\n' \
		"$(openssl rand -hex 32)" >"$RUNDIR/derper-restart/derper.json"
	start_derp_pair restart off false 127.0.0.1:18080 || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"
	check "relay tunnel carries HTTP" \
		test "$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")" = "hello-p2p"

	# Restart the far peer the way a phone restarts its entrypoint: the same
	# key file, a fresh process. Nothing tells the client side's session that
	# the peer it still holds is gone.
	kill_pid "$(cat "$RUNDIR/pids/p2p-restart-b")"
	sleep 1
	start_p2p B "p2p-restart-b" --addr 127.0.0.1:8003 \
		--derp "wss://$DERP_IP:443/derp" --key "$dir/keys/b" --tls.secure=false \
		--target 127.0.0.1:18080 --direct=false

	local t0=$SECONDS t1 body
	while :; do
		body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/" 3)
		[ "$body" = "hello-p2p" ] && break
		if [ $((SECONDS - t0)) -gt 90 ]; then
			fail "a restarted peer was not noticed in 90s"
			return
		fi
	done
	t1=$((SECONDS - t0))
	ok "tunnel recovered ${t1}s after the peer restarted"
	check "within one keepalive timeout of the restart" test "$t1" -le 25
}

scenario_derp_direct() {
	step "derp + STUN hole punch: a relay-only stream migrates to direct under loss"
	local dir="$RUNDIR/direct"
	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	start_derp_pair direct on true 127.0.0.1:18080 || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"

	# The canonical bytes come straight from the echo server (root namespace),
	# not through the tunnel, so the post-migration comparison is against the
	# source rather than against another tunneled read.
	local expect
	expect=$(curl -s --max-time 10 "http://$NET_GW:18081/bulk" | sha256sum | awk '{print $1}')

	# A transfer that outlives the punch: 1 MiB throttled to ~64 KiB/s (about
	# 16 s), opened before any stream has run, so it is what triggers the punch
	# and is still in flight when the pair flips to direct. Hashing the whole
	# stream end to end proves the cutover carried the bytes, not just that it
	# happened.
	local bulk="$dir/bulk.sha"
	( ns_run A curl -s --max-time 60 --limit-rate 64k -x http://127.0.0.1:8080 \
		"http://$NET_GW:18081/bulk" | sha256sum | awk '{print $1}' >"$bulk" ) &
	local bulkpid=$!
	PIDS+=("$bulkpid"); SCENARIO_PIDS+=("$bulkpid")

	if wait_status_ge A 127.0.0.1:8003 direct_peers 1 40; then
		ok "hole punch established a direct session mid-transfer"
	else
		fail "hole punch did not establish a direct session"
	fi

	# Loss at the cutover: the stream is already in flight under KCP, so a
	# window of loss must be repaired by retransmission, never surfaced.
	tc qdisc add dev v-A root netem loss 20% 2>/dev/null || fail "netem on v-A"
	tc qdisc add dev v-B root netem loss 20% 2>/dev/null || fail "netem on v-B"
	sleep 2
	tc qdisc del dev v-A root 2>/dev/null
	tc qdisc del dev v-B root 2>/dev/null

	wait "$bulkpid" 2>/dev/null
	check "the migrated 1 MiB transfer is byte-exact (sha256)" test "$(cat "$bulk")" = "$expect"

	# The migration reconstructed from the log alone (O1/O2): exactly one
	# relay->direct flip, its counter pinned at one migration and no fallback.
	local flips
	flips=$(grep -cE '"event":"path-change".*"to":"direct"' "$LOGDIR/p2p-direct-a.log" 2>/dev/null || true)
	check "the pair migrated exactly once" test "$flips" -eq 1
	check_grep "the migration records one migration and no fallback" \
		'"event":"path-change".*"to":"direct".*"migrations":1,"fallbacks":0' "$LOGDIR/p2p-direct-a.log"

	save_status A 127.0.0.1:8003 "$dir/status.json"
	check_grep "status shows a live direct peer" '"direct_peers":[1-9]' "$dir/status.json"
	check_grep "the diagnostic carries a punch trace" '"trace":\["' "$dir/status.json"
	# The two ends share a bridge here, with no NAT in between, so a peer can
	# only answer from an endpoint it announced. The shape verdict rides the
	# trace, which is on the wire, so this is a real assertion over the control
	# plane and not only in-process — and it needs a scenario where the punch
	# actually ran, which the relay-only one does not.
	check_not_grep "no peer answers from an endpoint it did not announce" "not announced" "$dir/status.json"

	local body
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "direct-capable tunnel carries HTTP" test "$body" = "hello-p2p"

	# `p2p doctor` is a control-plane client: it dials the running host, renders
	# the report and exits. The relay/STUN names come from the flags (a host does
	# not report its own config over Status).
	local report="$dir/doctor.txt"
	if ns_run A "$P2P_BIN" doctor --addr 127.0.0.1:8003 \
		--key "$dir/keys/a" --peer "$bkey" \
		--derp "wss://$DERP_IP:443/derp" --stun "$DERP_IP:3478" >"$report" 2>&1; then
		ok "p2p doctor queried the host"
	else
		fail "p2p doctor exited nonzero: $(cat "$report")"
	fi
	check_grep "doctor names the local identity" "^local key: *[A-Za-z0-9_-]{20}" "$report"
	check_grep "doctor reports the peer's direct path" "peer $bkey: direct path up" "$report"
	check_grep "doctor carries the punch trace" "^ +trace:" "$report"
	# The control plane's proto is frozen: it does not carry the NAT shape, so
	# the report says so rather than letting a zero read as "not observed".
	check_grep "doctor says the control plane does not carry the NAT shape" \
		"NAT shape: not reported by the control plane" "$report"

	# Kill the relay. A live direct path keeps the pair across the loss (H1):
	# the relay loss is counted and logged as suppressed, and the pair stays on
	# direct instead of being reset. It additionally keeps serving streams: the
	# loss tears down the per-build mux sessions on both ends (the pair's keys
	# and KCP epoch survive so a reconnect re-registers without a re-handshake),
	# and each end rebuilds its mux — the dialer on its next OpenStream, the
	# accepting side from the first inbound direct datagram (onDirectInbound,
	# the direct-side counterpart of the relay pump). So a stream opened while
	# the relay is down still flows over direct. See
	# .memory/notes/p2p-kcp-session-migration.md.
	# start_derper names its pid file after the tag ("direct"), not the binary.
	local dpid
	dpid=$(cat "$RUNDIR/pids/direct" 2>/dev/null || true)
	[ -n "$dpid" ] && kill_pid "$dpid"
	if wait_log "$LOGDIR/p2p-direct-a.log" '"event":"relay-loss".*"suppressed":true' 15; then
		ok "the relay loss is logged as suppressed by the live direct path"
	else
		fail "no suppressed relay-loss event after the relay died"
	fi
	check_not_grep "the relay loss does not reset the pair to relay" \
		'"event":"relay-loss".*"suppressed":false' "$LOGDIR/p2p-direct-a.log"
	save_status A 127.0.0.1:8003 "$dir/status-no-relay.json"
	check_grep "the pair keeps its direct path after the relay dies" \
		'"direct_peers":[1-9]' "$dir/status-no-relay.json"

	# Traffic continues over the surviving direct path: opening a stream now
	# rebuilds the mux on the dialer and, from the SYN datagram, on the accepting
	# side — no relay round trip is needed with the keys already settled.
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "a new stream is served over direct while the relay is down" test "$body" = "hello-p2p"
}

# scenario_quic_direct: the QUIC data plane (`--transport quic`) over a real
# derper, with the same topology and punch as derp-direct.
#
# Three phases:
#   1. relay-only: the first stream is what establishes the QUIC pair, and its
#      "open stream: quic" log names derp; the relay underlay is installed
#      before any direct underlay event exists.
#   2. migration: a 1 MiB transfer opened before the punch rides the relay while
#      the punch runs and migrates to the direct underlay mid-stream; the
#      sha256 comparison proves the cutover carried the bytes.
#   3. fallback: blocking the peers' UDP path (the relay is TCP to the derper)
#      leaves the direct heartbeats unanswered, the underlay watchdog retires
#      the direct path, and QUIC migrates back to the relay. A stream opened
#      afterwards is still served, and the relay bulk transfer is byte-exact.
#
# QUIC is strict: there is no KCP session at any point, so a "peer relay
# session up" line or a KCP transport label would be a regression.
scenario_quic_direct() {
	step "quic: relay-only, direct migration, direct->relay fallback"
	local dir="$RUNDIR/quic"
	mkdir -p "$dir"
	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	start_derp_pair quic on true 127.0.0.1:18080 "" quic || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"
	local alog="$LOGDIR/p2p-quic-a.log" blog="$LOGDIR/p2p-quic-b.log"

	# Phase 1: the first stream establishes the pair, so it can only ride the
	# relay. The relay underlay's install must precede any direct install.
	local body
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "relay-only QUIC stream carries HTTP" test "$body" = "hello-p2p"
	check_grep "the first QUIC stream opened over the relay" \
		'"msg":"open stream: quic".*"transport":"derp"' "$alog"
	check_grep "the relay underlay was installed" \
		'"msg":"quic underlay".*"underlay":"relay","event":"installed"' "$alog"
	local rln dln
	rln=$(grep -n '"underlay":"relay","event":"installed"' "$alog" | head -1 | cut -d: -f1)
	dln=$(grep -n '"underlay":"direct","event":"installed"' "$alog" | head -1 | cut -d: -f1)
	if [ -n "$rln" ] && { [ -z "$dln" ] || [ "$rln" -lt "$dln" ]; }; then
		ok "the relay was the first QUIC underlay"
	else
		fail "the relay underlay does not precede the direct underlay (relay=$rln direct=$dln)"
	fi
	check_not_grep "QUIC mode builds no KCP relay session on A" \
		'"msg":"peer relay session up"' "$alog"
	check_not_grep "QUIC mode builds no KCP relay session on B" \
		'"msg":"peer relay session up"' "$blog"

	# Phase 2: a transfer that outlives the punch. The throttled 1 MiB read
	# (~16 s) must start on the relay, so first prove no direct peer exists and
	# snapshot the path-change count. Only a count above that snapshot proves
	# the flip happened after the bulk started; checking `kill -0` at that
	# moment proves it happened while the transfer was still running, not
	# after it finished (the status wait allows up to 40 s, longer than the
	# transfer).
	local expect
	expect=$(curl -s --max-time 10 "http://$NET_GW:18081/bulk" | sha256sum | awk '{print $1}')
	local pcpat='"msg":"quic path-change".*"to":"direct"'
	if wait_status_eq A 127.0.0.1:8003 direct_peers 0 2; then
		ok "the pair is relay-only before the bulk transfer starts"
	else
		fail "a direct peer existed before the bulk transfer; the scenario cannot pin a mid-stream migration"
	fi
	local flips
	flips=$(grep -hE "$pcpat" "$alog" "$blog" 2>/dev/null | wc -l)
	local bulk="$dir/bulk.sha"
	( ns_run A curl -s --max-time 60 --limit-rate 64k -x http://127.0.0.1:8080 \
		"http://$NET_GW:18081/bulk" | sha256sum | awk '{print $1}' >"$bulk" ) &
	local bulkpid=$!
	PIDS+=("$bulkpid"); SCENARIO_PIDS+=("$bulkpid")

	if wait_status_ge A 127.0.0.1:8003 direct_peers 1 40; then
		ok "the punch installed a QUIC direct underlay"
	else
		fail "no QUIC direct session was established"
	fi
	# The relay->direct event is logged by whichever end is the QUIC client:
	# the server only changes its path once a direct datagram arrives, and at
	# install time it is still on relay, so its path-change pair can be
	# relay->relay (silent). Either end's event proves the migration, but only
	# a count above the pre-launch snapshot counts.
	if wait_log_any_count "$pcpat" $((flips + 1)) 15 "$alog" "$blog"; then
		if kill -0 "$bulkpid" 2>/dev/null; then
			ok "the pair migrated relay->direct while the bulk was still running"
		else
			fail "the relay->direct event only appeared after the bulk transfer finished"
		fi
	else
		fail "no new quic path-change to direct during the bulk transfer"
	fi
	wait "$bulkpid" 2>/dev/null
	check "the migrated 1 MiB transfer is byte-exact (sha256)" test "$(cat "$bulk")" = "$expect"

	save_status A 127.0.0.1:8003 "$dir/status-direct.json"
	check_grep "status shows a live direct peer" '"direct_peers":[1-9]' "$dir/status-direct.json"
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "the direct-capable QUIC tunnel carries HTTP" test "$body" = "hello-p2p"

	# Phase 3: kill only the direct path. The relay is TCP to the derper, so
	# the pair keeps its control plane while the direct heartbeat goes
	# unanswered. Both directions are dropped, so neither side can keep the
	# direct underlay alive by answering the other's heartbeat.
	local err
	if ! err=$(ns_run A iptables -I INPUT -s "$HOST_B_IP" -p udp -j DROP 2>&1); then
		fail "could not block the direct path (input): $err"; return
	fi
	if ! err=$(ns_run A iptables -I OUTPUT -d "$HOST_B_IP" -p udp -j DROP 2>&1); then
		# Undo the half-armed fault: the namespaces are shared by the later
		# scenarios, and a leftover drop would silence their UDP paths.
		ns_run A iptables -D INPUT -s "$HOST_B_IP" -p udp -j DROP 2>/dev/null || true
		fail "could not block the direct path (output): $err"; return
	fi
	ok "direct UDP path blocked; relay TCP path untouched"

	if wait_log_any '"msg":"quic path-change".*"to":"relay".*"reason":"heartbeat"' 30 \
		"$alog" "$blog"; then
		ok "the direct watchdog retired the silent path"
	else
		fail "no heartbeat-driven direct->relay fallback on either end"
		save_status A 127.0.0.1:8003 "$dir/status-stuck.json"
	fi
	if wait_status_eq A 127.0.0.1:8003 direct_peers 0 15; then
		ok "status shows relay-only after the fallback"
	else
		save_status A 127.0.0.1:8003 "$dir/status-fallback.json"
		fail "a direct peer survived the fallback: $(cat "$dir/status-fallback.json")"
	fi
	wait_status_ge A 127.0.0.1:8003 derp_peers 1 15 || fail "no relay peer after the fallback"

	# The QUIC connection (and its streams) survived the path loss: a fresh
	# stream is served over the relay, and a full bulk read comes back intact.
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "a stream opened after the fallback is served over the relay" \
		test "$body" = "hello-p2p"
	local n
	n=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/bulk" 20 | wc -c)
	check "the relay bulk transfer after the fallback is 1 MiB" test "$n" -eq 1048576
	check_not_grep "QUIC mode still built no KCP relay session on A" \
		'"msg":"peer relay session up"' "$alog"
	check_not_grep "QUIC mode still built no KCP relay session on B" \
		'"msg":"peer relay session up"' "$blog"

	ns_run A iptables -D INPUT -s "$HOST_B_IP" -p udp -j DROP 2>/dev/null || true
	ns_run A iptables -D OUTPUT -d "$HOST_B_IP" -p udp -j DROP 2>/dev/null || true
}

scenario_forward() {
	step "static --forward: raw TCP client on B reaches a service on A"
	local dir="$RUNDIR/fwd"
	start_echo - echo "$NET_GW:18081"
	# A holds the target (the peer gost); B forwards to A. No target on B.
	start_derp_pair fwd off false "" || return
	local akey
	akey=$(cat "$dir/a.pub")

	# Restart A with a target: inbound streams (opened by B's --forward) are
	# bridged to the peer gost, which reaches the echo server.
	local apid
	apid=$(cat "$RUNDIR/pids/p2p-fwd-a" 2>/dev/null || true)
	[ -n "$apid" ] && kill_pid "$apid"
	ns_bg A p2p-fwd-a "$P2P_BIN" --addr 127.0.0.1:8003 \
		--derp "wss://$DERP_IP:443/derp" --key "$dir/keys/a" --tls.secure=false \
		--direct=false --target 127.0.0.1:18080 --log.level debug --log.format json
	start_peer_gost A peer http 127.0.0.1:18080

	# Restart B with a forward listener bound to A's key.
	local bpid
	bpid=$(cat "$RUNDIR/pids/p2p-fwd-b" 2>/dev/null || true)
	[ -n "$bpid" ] && kill_pid "$bpid"
	ns_bg B p2p-fwd-b "$P2P_BIN" --addr 127.0.0.1:8003 \
		--derp "wss://$DERP_IP:443/derp" --key "$dir/keys/b" --tls.secure=false \
		--direct=false --forward "127.0.0.1:18081=$akey" --log.level debug --log.format json
	wait_tcp B 127.0.0.1 18081 15 || fail "forward listener did not listen"
	wait_tcp A 127.0.0.1 18080 10 || fail "peer gost did not listen"

	local body
	body=$(curl_proxy B http://127.0.0.1:18081 "http://$NET_GW:18081/")
	check "forward tunnel carries HTTP" test "$body" = "hello-p2p"
}

scenario_inner_matrix() {
	step "inner dialers: tcp/tls/ws/mtcp/mtls/mws over one relay pair"
	local dir="$RUNDIR/inner"
	start_echo - echo "$NET_GW:18081"
	start_derp_pair inner off false 127.0.0.1:18080 || return
	local bkey port=8080
	bkey=$(cat "$dir/b.pub")

	local d
	for d in tcp tls ws mtcp mtls mws; do
		local proto=$d
		[ "$d" = tcp ] && proto=http
		start_peer_gost B "peer-$d" "$proto" 127.0.0.1:18080
		wait_tcp B 127.0.0.1 18080 10 || fail "peer $d did not listen"
		gost_client_cfg "$dir/client-$d.yaml" 127.0.0.1:8003 "$bkey" "$d" "" "127.0.0.1:$port"
		start_gost A "client-$d" -C "$dir/client-$d.yaml"
		wait_tcp A 127.0.0.1 "$port" 10 || fail "client $d did not listen"
		local body
		body=$(curl_proxy A "http://127.0.0.1:$port" "http://$NET_GW:18081/")
		check "inner dialer $d carries HTTP" test "$body" = "hello-p2p"
		# The next dialer speaks a different protocol on the same port, so
		# stop this peer before starting the next.
		local pp
		pp=$(cat "$RUNDIR/pids/peer-$d" 2>/dev/null || true)
		[ -n "$pp" ] && kill_pid "$pp"
		port=$((port + 1))
	done
}

scenario_udp_tun() {
	step "datagram link: point-to-point tun link (udp inner)"
	local dir="$RUNDIR/tun"
	start_derp_pair tun off false "" || return
	local akey bkey
	akey=$(cat "$dir/a.pub"); bkey=$(cat "$dir/b.pub")

	# Both ends are tun clients: handler tun + chain (no forwarder), node
	# dialer udp / connector forward, node addr = the peer key.
	write_tun_client() { # file p2paddr peer net name
		cat >"$1" <<-YAML
			p2ps:
			  - name: p2p-1
			    plugin: {type: grpc, addr: $2}
			services:
			  - name: tun-0
			    addr: :0
			    handler: {type: tun, chain: chain-0}
			    listener:
			      type: tun
			      metadata: {name: $5, net: $4, mtu: 1420}
			chains:
			  - name: chain-0
			    hops:
			      - name: hop-0
			        nodes:
			          - name: node-0
			            addr: $3
			            dialer: {type: udp}
			            connector: {type: forward}
			            metadata: {p2p: p2p-1}
			log: {level: debug}
		YAML
	}
	write_tun_client "$dir/a.yaml" 127.0.0.1:8003 "$bkey" 10.10.0.1/30 p2pa
	write_tun_client "$dir/b.yaml" 127.0.0.1:8003 "$akey" 10.10.0.2/30 p2pb
	start_gost A gost-tun-a -C "$dir/a.yaml"
	start_gost B gost-tun-b -C "$dir/b.yaml"

	sleep 3
	local p
	if p=$(ns_run A ping -c1 -W4 10.10.0.2 2>&1); then ok "tun link: A pings B (10.10.0.2)"; else fail "tun link ping failed: $p"; fi
	if p=$(ns_run B ping -c1 -W4 10.10.0.1 2>&1); then ok "tun link: B pings A (10.10.0.1)"; else fail "tun link ping failed: $p"; fi
	check_grep "datagram link is live on A" 'datagram link up' "$LOGDIR/p2p-tun-a.log"
	check_grep "datagram link is live on B" 'datagram link up' "$LOGDIR/p2p-tun-b.log"
}

# scenario_udp_tun_loss: the point-to-point tun link again, with tc netem packet
# loss on the veths, to pin how the datagram link behaves on a lossy path.
# Moderate loss must not tear the link down (the smux keepalive, sent every few
# seconds, still gets through and the session only gives up after 15s of
# silence); a blackout past that timeout must end the link, and the presenter
# must rebuild it once the path is clear. This is the shape a network switch
# leaves behind, and the bound the tun's re-registration rides on.
scenario_udp_tun_loss() {
	step "datagram link under packet loss (netem)"
	local dir="$RUNDIR/tun-loss"
	start_derp_pair tun-loss off false "" || return
	local akey bkey
	akey=$(cat "$dir/a.pub"); bkey=$(cat "$dir/b.pub")

	write_tun_client() { # file p2paddr peer net name
		cat >"$1" <<-YAML
			p2ps:
			  - name: p2p-1
			    plugin: {type: grpc, addr: $2}
			services:
			  - name: tun-0
			    addr: :0
			    handler: {type: tun, chain: chain-0}
			    listener:
			      type: tun
			      metadata: {name: $5, net: $4, mtu: 1420}
			chains:
			  - name: chain-0
			    hops:
			      - name: hop-0
			        nodes:
			          - name: node-0
			            addr: $3
			            dialer: {type: udp}
			            connector: {type: forward}
			            metadata: {p2p: p2p-1}
			log: {level: debug}
		YAML
	}
	write_tun_client "$dir/a.yaml" 127.0.0.1:8003 "$bkey" 10.10.0.1/30 p2pa
	write_tun_client "$dir/b.yaml" 127.0.0.1:8003 "$akey" 10.10.0.2/30 p2pb
	start_gost A gost-tun-a -C "$dir/a.yaml"
	start_gost B gost-tun-b -C "$dir/b.yaml"

	sleep 3
	if ns_run A ping -c1 -W4 10.10.0.2 >/dev/null 2>&1; then ok "tun link up before loss"; else fail "tun link down before loss"; fi

	# Moderate loss: the session survives, so the link stays up and traffic
	# still flows.
	tc qdisc add dev v-A root netem loss 30% 2>/dev/null || fail "netem on v-A"
	tc qdisc add dev v-B root netem loss 30% 2>/dev/null || fail "netem on v-B"
	sleep 20
	if ns_run A ping -c2 -W8 10.10.0.2 >/dev/null 2>&1; then ok "tun link survives 30% loss"; else fail "tun link broke under 30% loss"; fi

	# Blackout past the keepalive timeout: the session gives up and the link
	# ends.
	tc qdisc change dev v-A root netem loss 100%
	tc qdisc change dev v-B root netem loss 100%
	sleep 25
	check_grep "datagram link ended under a blackout" 'datagram link down' "$LOGDIR/p2p-tun-loss-a.log"

	# Clear the path: the presenter reopens and the link is rebuilt.
	tc qdisc del dev v-A root 2>/dev/null
	tc qdisc del dev v-B root 2>/dev/null
	sleep 20
	if ns_run A ping -c2 -W8 10.10.0.2 >/dev/null 2>&1; then ok "tun link restored after the blackout"; else fail "tun link did not restore"; fi
}

scenario_udp_outlet() {
	step "udp target outlet: NAT'd spokes reach one tun server"
	local dir="$RUNDIR/outlet"
	mkdir -p "$dir"
	start_derp_pair outlet off false "" || return
	local akey bkey
	akey=$(cat "$dir/a.pub"); bkey=$(cat "$dir/b.pub")

	# Outlet B: a tun SERVER on udp, and a p2p host with a udp target at it.
	cat >"$dir/server.yaml" <<-YAML
		services:
		  - name: tun-server
		    addr: 127.0.0.1:8421
		    handler:
		      type: tun
		      auther: tun-auth
		      metadata: {keepalive: true, ttl: 10s}
		    listener:
		      type: tun
		      metadata: {name: p2psrv, net: 10.10.0.1/24, mtu: 1420}
		authers:
		  - name: tun-auth
		    auths:
		      - username: 10.10.0.2
		        password: spoke-pass
		log: {level: debug}
	YAML
	start_gost B gost-srv -C "$dir/server.yaml"
	# A local address behind the outlet, so the spoke's route has a destination.
	ns_run B ip link add lan0 type dummy 2>/dev/null || true
	ns_run B ip addr add 192.168.50.1/24 dev lan0 2>/dev/null || true
	ns_run B ip link set lan0 up

	# Restart B's p2p host with a udp target (the outlet). The base pair
	# started it without one.
	local bpid
	bpid=$(cat "$RUNDIR/pids/p2p-outlet-b" 2>/dev/null || true)
	[ -n "$bpid" ] && kill_pid "$bpid"
	ns_bg B p2p-outlet-b "$P2P_BIN" --addr 127.0.0.1:8003 \
		--derp "wss://$DERP_IP:443/derp" --key "$dir/keys/b" --tls.secure=false \
		--direct=false --target udp://127.0.0.1:8421 --log.level debug --log.format json
	wait_log "$LOGDIR/gost-srv.log" 'listening on 127.0.0.1:8421' 20 || fail "tun server did not listen"

	# Spoke A: a stock tun client with keepalive + the shared passphrase,
	# routing the outlet's LAN through the tunnel.
	cat >"$dir/spoke.yaml" <<-YAML
		p2ps:
		  - name: p2p-1
		    plugin: {type: grpc, addr: 127.0.0.1:8003}
		services:
		  - name: tun-0
		    addr: :0
		    handler: {type: tun, chain: chain-0, metadata: {keepalive: true, ttl: 10s, passphrase: spoke-pass}}
		    listener:
		      type: tun
		      metadata: {name: p2pspoke, net: 10.10.0.2/24, mtu: 1420, route: 192.168.50.0/24}
		chains:
		  - name: chain-0
		    hops:
		      - name: hop-0
		        nodes:
		          - name: node-0
		            addr: $bkey
		            dialer: {type: udp}
		            connector: {type: forward}
		            metadata: {p2p: p2p-1}
		log: {level: debug}
	YAML
	start_gost A gost-spoke -C "$dir/spoke.yaml"
	# The spoke is only routable once its keepalive registers a route at the
	# outlet; that can take up to one ttl interval.
	wait_log "$LOGDIR/gost-srv.log" 'new route: 10.10.0.2' 25 || fail "spoke route never registered at the outlet"
	sleep 1

	local p
	if p=$(ns_run A ping -c1 -W5 10.10.0.1 2>&1); then ok "outlet: spoke reaches the tun server (10.10.0.1)"; else fail "outlet ping failed: $p"; fi
	if p=$(ns_run A ping -c1 -W5 192.168.50.1 2>&1); then ok "outlet: spoke reaches the LAN behind it (192.168.50.1)"; else fail "outlet LAN ping failed: $p"; fi
}

scenario_ipv6_direct() {
	step "IPv6 direct: no STUN, direct path via global v6 egress"
	local dir="$RUNDIR/v6"
	mkdir -p "$dir"
	# Give the bridge and both hosts a v6 prefix with a default route so
	# detectV6Egress() finds a global egress (ULA is global unicast to Go).
	ip -6 addr add fd00::1/64 dev "$BRIDGE" 2>/dev/null || true
	ns_run A ip -6 addr add fd00::2/64 dev eth0 2>/dev/null || true
	ns_run B ip -6 addr add fd00::3/64 dev eth0 2>/dev/null || true
	ns_run A ip -6 route add default via fd00::1 2>/dev/null || true
	ns_run B ip -6 route add default via fd00::1 2>/dev/null || true
	# The addresses are tentative until duplicate-address detection finishes,
	# and a tentative address is not a usable egress source, so wait for DAD.
	local i
	for i in $(seq 1 50); do
		ns_run A ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -q 'src fd00::2' &&
			ns_run B ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -q 'src fd00::3' && break
		sleep 0.2
	done
	ns_run A ip -6 route get 2001:4860:4860::8888 >"$dir/a.route" 2>&1 || true
	ns_run B ip -6 route get 2001:4860:4860::8888 >"$dir/b.route" 2>&1 || true
	check_grep "A has a usable global v6 egress" 'src fd00::2' "$dir/a.route"
	check_grep "B has a usable global v6 egress" 'src fd00::3' "$dir/b.route"

	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	# stun=off: the only direct candidate source is the v6 egress, and the
	# family is opt-in, so both hosts must ask for it.
	start_derp_pair v6 off true 127.0.0.1:18080 true || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"
	local body
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "v6-direct tunnel carries HTTP" test "$body" = "hello-p2p"

	if wait_status_ge A 127.0.0.1:8003 direct_peers 1 40; then
		ok "v6 direct session established without STUN"
	else
		fail "v6 direct session not established"
	fi
	# Prove the dialed candidate really was IPv6 and not a v4 fallback: with STUN
	# off the only candidate source is the v6 egress, and the peer must announce
	# an fd00:: endpoint for A to dial.
	check_grep "direct candidate is the peer's IPv6 egress" \
		'direct punch: peer candidates.*fd00::' "$LOGDIR/p2p-v6-a.log"
}

# --- runner ------------------------------------------------------------------

# The shape measured on the phone/hub pair that took 45 minutes to recover from:
# the direct underlay's heartbeat was answered, so every recency-based check
# read the path healthy, while its KCP plane returned nothing at all. ⑤ closes
# it without recency — a dead path and an idle one show the same silence, so no
# timestamp can tell them apart — by reading the per-underlay byte counters
# instead: a path that keeps sending while receiving nothing is not carrying.
#
# The unit tests (direct_oneway_test.go) hold the predicate's false positives,
# which matters more than its true positive: a predicate that retired
# one-directional traffic, or a healthy path between ACKs, would turn the
# sticky-direct fix into a flap. This scenario holds what only a real network
# can produce — the shape itself, at the packet level.
#
# A heartbeat is a 4-byte magic plus an 8-byte token: 12 bytes of payload, 40
# bytes on the wire counting the IP and UDP headers, and it is consumed inside
# the underlay's read loop so it never reaches KCP's byte counters. A KCP
# segment is at least 25 bytes of payload — 53 on the wire — and cannot be
# mistaken for one. So the fault, armed on A's inbound from B only, passes
# exactly the heartbeat and drops the rest of what B sends on the direct path:
# heartbeats still round-trip, KCP gets nothing back, and nothing about the
# underlay looks dead to anything but the counters.
#
# The killer detail is where the send counter sits: relayKCPPair.WriteTo bumps
# directBytesSent *before* handing the datagram to the socket, so a datagram
# the kernel drops on its way out still advances it. That is what makes a
# network-level drop produce the production shape exactly, rather than a
# quieter cousin of it.
#
# The window is production's 60s, but the scenario runs it at 25s via
# P2P_DIRECT_ONE_WAY_WINDOW (see relaykcp.go). A container cannot sustain 60s
# of continuous one-way sending: A's peer smux session gives up after 15s of
# silence (the same 15s the loss scenario pins), so once the app stream dies it
# is KCP retransmits — not application writes — that keep directBytesSent
# moving, and IKCP's RTO backoff turns those into 1-2s gaps well before 60s.
# The longest continuous run measured here is ~43s, so 25s trips with margin.
# The predicate's exact 60s semantics stay pinned by direct_oneway_test.go; the
# e2e is the only place the full path — pumpDirect -> directOneWayDead -> the
# engine's retirement -> relay fallback -> recovery — is exercised end to end.
scenario_oneway_direct() {
	step "one-way-dead direct path: the byte counters retire it, the relay catches it"
	local dir="$RUNDIR/oneway"
	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	# Shrink ⑤'s window for the run (see the header). The p2p processes
	# inherit it at fork; unset immediately after so no later scenario sees it.
	export P2P_DIRECT_ONE_WAY_WINDOW=25s
	start_derp_pair oneway on true 127.0.0.1:18080
	local pair_rc=$?
	unset P2P_DIRECT_ONE_WAY_WINDOW
	[ "$pair_rc" = 0 ] || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	# A plain UDP echo on B's host address. It measures the fault's own shape
	# with nothing from p2p in the way, so "heartbeats still survive the fault"
	# is a measurement rather than an assumption — the alternative is asserting
	# a retirement without being able to see why it fired.
	ns_bg B udpecho "$HELPER_BIN" udp "$HOST_B_IP:19999"

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"

	# The upload starts before anything is asserted, because the punch is
	# driven by the peer's registration plus traffic, not by the hosts merely
	# knowing about each other. derp-direct waits the same way for the same
	# reason; a pair punched and then left idle for 40s proves nothing.
	head -c 8M /dev/zero >"$dir/body.bin"
	( ns_run A curl -s --max-time 400 --limit-rate 64k -x http://127.0.0.1:8080 \
		--data-binary @"$dir/body.bin" "http://$NET_GW:18081/" \
		>"$dir/up.body" ) &
	local bulkpid=$!
	PIDS+=("$bulkpid"); SCENARIO_PIDS+=("$bulkpid")

	if wait_status_ge A 127.0.0.1:8003 direct_peers 1 40; then
		ok "the transfer rides a punched direct session"
	else
		fail "no direct session established for the transfer"; return
	fi

	# The probe answers before the fault, or a silence afterwards proves
	# nothing about the filter.
	probe_reply "$dir/pre.reply" 12
	check "the probe echo answers before the fault" \
		test "$(wc -c <"$dir/pre.reply")" -eq 12

	# Baseline: the direct plane really carries bytes before anything is
	# filtered, so a silent data plane afterwards is the fault and not the
	# topology. direct_bytes_rcvd is not exposed over gRPC (the proto is
	# frozen), so this is the log's own accounting rather than a status field.
	save_status A 127.0.0.1:8003 "$dir/status-before.json"
	check_grep "the direct plane is carrying before the fault" \
		'"direct_peers":[1-9]' "$dir/status-before.json"

	# Escape hatch for the Phase-1 control run: with P2P_E2E_NO_FAULT=1 the
	# fault is never armed, so the same workload runs with a healthy pair. It
	# exists to answer one question — is the 15s relay-session churn the filter,
	# or the workload? — and it is not a scenario, so it asserts nothing.
	if [ "${P2P_E2E_NO_FAULT:-0}" = 1 ]; then
		ok "fault skipped (P2P_E2E_NO_FAULT): control run, healthy direct pair"
	else
		# One end only: A's inbound from B. The upload still reaches B and B
		# stays healthy; only A's receive counter freezes. See ONEWAY_MAX_CTRL.
		arm_oneway_fault A "$HOST_B_IP" || return
		ok "one-way fault armed on A: from B only a heartbeat-sized datagram passes"
	fi

	# The fault's shape, measured directly. The 12-byte probe must still
	# round-trip — that is the heartbeat, and its survival is what makes this
	# ⑤ rather than a dead path: the underlay sees an answered echo and never
	# retires the path for idle. Everything KCP-shaped must be swallowed,
	# including a datagram the size of a KCP ACK, because a receive counter
	# that still moves is a path that still looks two-way.
	sleep 2
	probe_reply "$dir/hb.reply" 12
	check "a heartbeat-sized datagram still round-trips under the fault" \
		test "$(wc -c <"$dir/hb.reply")" -eq 12
	probe_reply "$dir/ctrl.reply" 64
	check "a KCP-control-sized datagram is swallowed by the fault" \
		test "$(wc -c <"$dir/ctrl.reply")" -eq 0
	probe_reply "$dir/big.reply" 512
	check "a data-sized datagram is swallowed by the fault" \
		test "$(wc -c <"$dir/big.reply")" -eq 0

	# The whole point: the direct path's heartbeat is answered — the 12-byte
	# probe above just proved it on the same filter — while its data plane
	# returns nothing. Nothing recency-based can act on that, because an idle
	# path reads identically. The counters can.
	local alog="$LOGDIR/p2p-oneway-a.log"
	if wait_log "$alog" '"event":"path-change".*"to":"relay".*"reason":"direct-idle"' 150; then
		ok "the answered-heartbeat, data-silent direct path was retired"
	else
		fail "no direct-idle fallback after 150s of a one-way-dead direct path"
		save_status A 127.0.0.1:8003 "$dir/status-stuck.json"
	fi

	# ⑤ is time-gated: the tracker trips only after directOneWayWindow of a
	# moving send counter against a frozen receive counter — 25s here, the
	# production 60s shrunk for the run (see the header). A direct path retired
	# seconds after it installed is the heartbeat-unanswered path — a different
	# failure wearing the same "direct-idle" reason — so the time between the
	# underlay's install and that idle is the only thing separating the two.
	# Without this the scenario passes on the very defect it exists to catch,
	# which is exactly what happened before the threshold was narrowed: the
	# heartbeat-unanswered retirement fired at ~11s, the one-way one now fires
	# past the 25s window, so 20s separates them.
	local iln idln t_inst t_idle
	read -r iln idln < <(awk '
		/"event":"direct-underlay"/ && /"state":"installed"/ { iln = NR }
		/"reason":"direct-idle"/ { print iln, NR; exit }
	' "$alog")
	if [ "${iln:-0}" -gt 0 ] && [ "${idln:-0}" -gt 0 ]; then
		t_inst=$(date -d "$(sed -n "${iln}p" "$alog" | sed -n 's/.*"time":"\([^"]*\)".*/\1/p')" +%s)
		t_idle=$(date -d "$(sed -n "${idln}p" "$alog" | sed -n 's/.*"time":"\([^"]*\)".*/\1/p')" +%s)
		check "the direct path outlived the one-way window before retiring ($((t_idle - t_inst))s)" \
			test $((t_idle - t_inst)) -ge 20
	else
		fail "could not locate the underlay install preceding the direct-idle"
	fi

	# And it recovers without a human flipping the direct toggle. With the
	# fault still armed the pair flaps rather than settling: every re-punch is
	# re-elected direct on the first inbound heartbeat, so a request issued
	# during a direct phase reaches B and has B's reply dropped, while one
	# issued during a relay phase completes end to end. Retrying across several
	# windows makes the relay fallback observable instead of a coin flip —
	# success inside the fault is the assertion the 45-minute field case could
	# not make. (The bulk upload is not a recovery signal: it stalls at the KCP
	# window once B's acknowledgements stop, so its response never comes.)
	kill "$bulkpid" 2>/dev/null
	wait "$bulkpid" 2>/dev/null || true
	local i relay_ok=0
	for i in $(seq 1 15); do
		if [ "$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/" 4)" = "hello-p2p" ]; then
			relay_ok=$((relay_ok + 1))
		fi
	done
	check "requests complete over the relay while the fault is still armed ($relay_ok/15)" \
		test "$relay_ok" -ge 1

	# Clearing the fault has to leave the sticky-direct behaviour intact —
	# ⑤ must not become a reason to punch-hole every healthy pair on a timer.
	# Once data actually flows again the pair re-elects direct, and a later
	# transfer rides it.
	clear_oneway_fault A "$HOST_B_IP"
	ok "fault cleared"
	( ns_run A curl -s --max-time 30 -x http://127.0.0.1:8080 \
		"http://$NET_GW:18081/" >"$dir/after.body" ) &
	local afterpid=$!
	PIDS+=("$afterpid"); SCENARIO_PIDS+=("$afterpid")
	wait "$afterpid" 2>/dev/null
	check "the tunnel carries a request after the fault clears" \
		test "$(cat "$dir/after.body" 2>/dev/null)" = "hello-p2p"
	if wait_log "$alog" '"event":"path-change".*"reason":"first-direct-datagram"' 90; then
		ok "the pair re-elected direct once the data plane flowed again"
	else
		fail "the pair never returned to direct after the fault cleared"
	fi
}

# probe_reply <outfile> [len]: send one datagram of len bytes to B's UDP echo
# and keep what comes back. Used to measure the fault's shape directly.
probe_reply() {
	local out=$1 n=${2:-12}
	head -c "$n" /dev/urandom |
		ns_run A nc -u -w2 "$HOST_B_IP" 19999 >"$out" 2>/dev/null || true
}

# The threshold has to be exactly one heartbeat wide — 40 bytes on the wire,
# including the IP and UDP headers — because that is the only datagram that may
# survive:
#   - the 12-byte heartbeat (4-byte magic + 8-byte token) is consumed inside the
#     underlay's own read loop, so it never reaches KCP's byte counters. An
#     answered heartbeat keeps hbLive() true — the path reads as alive — while
#     directBytesRcvd stays frozen. That is the whole shape ⑤ is defined on:
#     alive by echo, dead by counters.
#   - everything else is dropped, the control plane included. An earlier filter
#     passed anything up to 200 bytes "so the KCP keepalives survive", and that
#     is exactly what kept ⑤ from ever latching: KCP's ACKs and window probes
#     are 52-76 bytes on the wire, slipped under the 200-byte ceiling, advanced
#     directBytesRcvd, and tripped directOneWayDead's `rcvd >` clear on every
#     tick. Measured over a 168s run with that filter: ⑤ did not fire once.
# A KCP-control-sized datagram being swallowed is the point here, not a defect:
# a one-way path that still gets KCP back is not one-way.
#
# The fault is armed on ONE end only. Arming both ends starves the pair's smux
# session from the side that sends the keepalives, the relay session churns every
# 15s, and the engine replaces the pair's registration on the churn threshold
# (engine.go:2657) — retiring the underlay ~90s in and abandoning the direct path
# before the 60s window it was armed to exercise. Leaving A->B open keeps the
# observed pair fed from the direction that must stay healthy, so the only thing
# the counters see is the one-way shape.
ONEWAY_MAX_CTRL=40

arm_oneway_fault() {
	local ns=$1 peerip=$2 t src err
	for t in iptables ip6tables; do
		# ip6tables rejects a bare v4 address, so the v6 pass uses the
		# v4-mapped spelling. Without it the v6 leg cannot be armed at all,
		# and a peer whose direct socket is a mapped v6 one would slip past
		# the fault entirely.
		src=$peerip
		[ "$t" = ip6tables ] && src="::ffff:$peerip"
		err=$(ns_run "$ns" "$t" -A INPUT -s "$src" -p udp -m length --length "0:$ONEWAY_MAX_CTRL" -j ACCEPT 2>&1) ||
			{ fail "could not arm the heartbeat pass-through in $ns ($t): $err"; return 1; }
		err=$(ns_run "$ns" "$t" -A INPUT -s "$src" -p udp -j DROP 2>&1) ||
			{ fail "could not arm the data-plane drop in $ns ($t): $err"; return 1; }
	done
}

clear_oneway_fault() {
	local ns=$1 peerip=$2 t src
	for t in iptables ip6tables; do
		src=$peerip
		[ "$t" = ip6tables ] && src="::ffff:$peerip"
		ns_run "$ns" "$t" -D INPUT -s "$src" -p udp -j DROP 2>/dev/null || true
		ns_run "$ns" "$t" -D INPUT -s "$src" -p udp -m length --length "0:$ONEWAY_MAX_CTRL" -j ACCEPT 2>/dev/null || true
	done
}

run_scenario() {
	local name=$1 rc=0
	SCENARIO=$name
	local before=$FAILURES
	"scenario_${name//-/_}" || rc=$?
	scenario_cleanup
	# A non-zero return is a failure even if the scenario never called fail()
	# (e.g. a missing function), so a typo in a scenario name cannot report PASS.
	[ "$rc" = 0 ] || fail "scenario $name exited with status $rc"
	if [ "$FAILURES" = "$before" ]; then
		say "${C_OK}scenario $name: PASS${C_RST}"
	else
		say "${C_ERR}scenario $name: FAIL ($((FAILURES - before)) assertion(s))${C_RST}"
	fi
}

main() {
	say "p2p e2e  run=$RUN_ID  work=$WORK"
	# Clear leftovers from a previous crashed run before starting, so stale
	# processes cannot satisfy wait_tcp/wait_log or hold our ports.
	reap_stale
	build_binaries
	extract_derper
	say "binaries: p2p=$P2P_BIN gost=$GOST_BIN helper=$HELPER_BIN derper=$DERPER_BIN"

	if [ -n "$ONLY" ]; then
		SCENARIOS=("$ONLY")
	fi

	# Namespaces are shared by every scenario; the stub scenario uses the root
	# namespace but the rest need A/B.
	local needs_net=0
	for s in "${SCENARIOS[@]}"; do [ "$s" != stub ] && needs_net=1; done
	[ "$needs_net" = 1 ] && setup_net

	for s in "${SCENARIOS[@]}"; do
		run_scenario "$s"
	done

	say ""
	if [ "$FAILURES" = 0 ]; then
		say "${C_OK}ALL PASS${C_RST} ($PASSED assertions)"
		rc=0
	else
		say "${C_ERR}$FAILURES FAILED${C_RST} / $((PASSED + FAILURES)) assertions"
		rc=1
	fi
	say "logs: $LOGDIR"
	if [ "$KEEP" = 0 ]; then
		# Keep only the last few runs to bound disk.
		ls -1dt "$WORK"/runs/*/ 2>/dev/null | tail -n +6 | xargs -r rm -rf
	fi
	return $rc
}

main
exit $?
