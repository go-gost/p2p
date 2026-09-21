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
SCENARIOS=(stub derp-relay derp-direct forward inner-matrix udp-tun udp-outlet ipv6-direct)

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
	(cd "$P2P_DIR" && "$GO" build -o "$P2P_BIN" .) || { echo "p2p build failed" >&2; exit 1; }
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
# start_derp_pair <tag> <stun:on|off> <direct:true|false> <b-target>
start_derp_pair() {
	local tag=$1 stun=$2 direct=$3 btarget=$4
	local dir="$RUNDIR/$tag"
	mkdir -p "$dir/keys"
	start_derper "$tag" "$stun" || return 1
	# B: bridges inbound tunnels to the peer gost (or holds a udp target).
	local bargs=(--addr 127.0.0.1:8003 --derp "wss://$DERP_IP:443/derp"
		--key "$dir/keys/b" --tls.secure=false)
	[ -n "$btarget" ] && bargs+=(--target "$btarget")
	[ "$direct" = false ] && bargs+=(--direct=false)
	[ "$stun" = on ] && bargs+=(--stun "$DERP_IP:3478")
	start_p2p B "p2p-$tag-b" "${bargs[@]}"
	# A: client side control plane.
	local aargs=(--addr 127.0.0.1:8003 --derp "wss://$DERP_IP:443/derp"
		--key "$dir/keys/a" --tls.secure=false)
	[ "$direct" = false ] && aargs+=(--direct=false)
	[ "$stun" = on ] && aargs+=(--stun "$DERP_IP:3478")
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
	# A non-mux tunnel must leave no residue once the request finishes.
	if wait_status_eq A 127.0.0.1:8003 tunnels 0 15; then
		ok "tunnel record reclaimed after the stream ends (zero residue)"
	else
		save_status A 127.0.0.1:8003 "$dir/status-after.json"
		fail "tunnel count did not return to zero: $(cat "$dir/status-after.json")"
	fi
}

scenario_derp_direct() {
	step "derp + STUN hole punch: direct path, then kill the relay"
	local dir="$RUNDIR/direct"
	start_echo - echo "$NET_GW:18081"
	start_peer_gost B peer http 127.0.0.1:18080
	start_derp_pair direct on true 127.0.0.1:18080 || return
	local bkey
	bkey=$(cat "$dir/b.pub")

	gost_client_cfg "$dir/client.yaml" 127.0.0.1:8003 "$bkey" tcp "" 127.0.0.1:8080
	start_gost A client -C "$dir/client.yaml"
	wait_tcp A 127.0.0.1 8080 15 || fail "client proxy did not listen"

	local body
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "direct-capable tunnel carries HTTP" test "$body" = "hello-p2p"

	if wait_status_ge A 127.0.0.1:8003 direct_peers 1 40; then
		ok "hole punch established a direct session"
	else
		fail "hole punch did not establish a direct session"
	fi
	save_status A 127.0.0.1:8003 "$dir/status.json"
	check_grep "status shows a live direct peer" '"direct_peers":[1-9]' "$dir/status.json"

	# Kill the relay: the direct session must survive.
	local dpid
	dpid=$(cat "$RUNDIR/pids/derper-direct" 2>/dev/null || true)
	[ -n "$dpid" ] && kill_pid "$dpid"
	sleep 1
	body=$(curl_proxy A http://127.0.0.1:8080 "http://$NET_GW:18081/")
	check "traffic continues after the relay dies (direct survives)" test "$body" = "hello-p2p"
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
	step "datagram channel: point-to-point tun link (udp inner)"
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
	check_grep "datagram channel is live on A" 'channel up|channel role' "$LOGDIR/p2p-tun-a.log"
	check_grep "datagram channel is live on B" 'channel up|channel role' "$LOGDIR/p2p-tun-b.log"
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
	# stun=off: the only direct candidate source is the v6 egress.
	start_derp_pair v6 off true 127.0.0.1:18080 || return
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
