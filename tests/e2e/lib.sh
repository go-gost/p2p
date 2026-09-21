#!/usr/bin/env bash
# Shared helpers for the p2p e2e suite. Sourced by run.sh; not executable on
# its own. Every process the suite starts is tracked by PID so cleanup never
# relies on pkill across namespaces (PID namespaces are shared, so pkill -f
# would kill the other side too -- see .memory/notes/p2p-e2e-nested-netns.md).

# --- pretty output -----------------------------------------------------------

if [ -t 1 ]; then
	C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
	C_OK=; C_ERR=; C_DIM=; C_RST=
fi

PASSED=0
FAILURES=0
SCENARIO=""
PIDS=()          # every process started (killed at global cleanup)
SCENARIO_PIDS=() # processes started by the current scenario

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s== %s%s\n' "$C_DIM" "$*" "$C_RST"; }
ok()   { PASSED=$((PASSED + 1)); printf '  %sPASS%s %s\n' "$C_OK" "$C_RST" "$*"; }
fail() {
	FAILURES=$((FAILURES + 1))
	printf '  %sFAIL%s %s\n' "$C_ERR" "$C_RST" "$*"
}
# check <desc> <cmd...>: run cmd, PASS on exit 0.
check() {
	local d=$1; shift
	if "$@"; then ok "$d"; else fail "$d"; fi
}
# check_grep <desc> <pattern> <file>
check_grep() {
	if grep -qE "$2" "$3" 2>/dev/null; then ok "$1"; else fail "$1 (no /$2/ in $3)"; fi
}
# check_not_grep <desc> <pattern> <file>
check_not_grep() {
	if grep -qE "$2" "$3" 2>/dev/null; then fail "$1 (found /$2/ in $3)"; else ok "$1"; fi
}

# --- namespaces --------------------------------------------------------------
# Two modes: real `ip netns` (root, clean) and a holder process (uid != 0,
# where `ip netns add` cannot write /run/netns). Both are entered with
# nsenter -t <pid> -n so backgrounded processes keep the target PID (exec).

NS_MODE=""
declare -A NS_PID=()
NS_NAMES=()

ns_probe_mode() {
	if ip netns add p2p-e2e-probe 2>/dev/null; then
		ip netns del p2p-e2e-probe 2>/dev/null
		NS_MODE=ip
	else
		NS_MODE=holder
	fi
}

ns_add() {
	local n=$1
	NS_NAMES+=("$n")
	if [ "$NS_MODE" = ip ]; then
		ip netns add "$n"
		ip -n "$n" link set lo up
		return
	fi
	local wrap="unshare -n"
	[ "$(id -u)" != 0 ] && wrap="unshare -Ur -n"
	$wrap sh -c 'ip link set lo up; exec sleep 100000' >/dev/null 2>&1 &
	NS_PID[$n]=$!
	PIDS+=("${NS_PID[$n]}")
	local i
	for i in $(seq 1 50); do [ -e "/proc/${NS_PID[$n]}/ns/net" ] && break; sleep 0.1; done
}

ns_pid() { echo "${NS_PID[$1]}"; }

ns_run() { # <ns> <cmd...>
	local n=$1; shift
	if [ "$NS_MODE" = ip ]; then
		ip netns exec "$n" "$@"
	else
		nsenter -t "${NS_PID[$n]}" -n "$@"
	fi
}

ns_del() {
	local n=$1
	if [ "$NS_MODE" = ip ]; then ip netns del "$n" 2>/dev/null || true; fi
}

# ns_bg <ns> <logname> <cmd...>: run cmd inside ns, log to $LOGDIR/<logname>.log.
# ns may be "-" for the root namespace.
ns_bg() {
	local n=$1 name=$2; shift 2
	if [ "$n" = "-" ]; then bg "$name" "$@"; return; fi
	local log="$LOGDIR/$name.log"
	if [ "$NS_MODE" = ip ]; then
		ip netns exec "$n" "$@" >>"$log" 2>&1 &
	else
		nsenter -t "${NS_PID[$n]}" -n "$@" >>"$log" 2>&1 &
	fi
	local pid=$!
	PIDS+=("$pid"); SCENARIO_PIDS+=("$pid")
	echo "$pid" >"$RUNDIR/pids/$name"
}

# bg <logname> <cmd...>: run cmd in the root namespace.
bg() {
	local name=$1; shift
	local log="$LOGDIR/$name.log"
	"$@" >>"$log" 2>&1 &
	local pid=$!
	PIDS+=("$pid"); SCENARIO_PIDS+=("$pid")
	echo "$pid" >"$RUNDIR/pids/$name"
}

# --- process lifecycle -------------------------------------------------------

kill_pid() {
	local p=$1
	[ -z "$p" ] && return 0
	kill "$p" 2>/dev/null || true
	local i
	for i in $(seq 1 30); do
		kill -0 "$p" 2>/dev/null || return 0
		sleep 0.1
	done
	kill -9 "$p" 2>/dev/null || true
}

scenario_cleanup() {
	local p
	for p in "${SCENARIO_PIDS[@]:-}"; do [ -n "$p" ] && kill_pid "$p"; done
	SCENARIO_PIDS=()
}

cleanup_all() {
	scenario_cleanup
	local p
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill_pid "$p"; done
	net_teardown
	reap_stale
}

# reap_stale kills processes left by a previous run whose EXIT trap never fired
# (e.g. SIGKILL). Only the suite's private binary paths are matched -- they live
# under $WORK/bin and $WORK/derper-root -- because a user-supplied --gost-bin /
# --p2p-bin / --derper-bin may point at a system binary shared with other users,
# which must never be touched. Called at startup (to clear a crashed
# predecessor, the actual poison scenario) and at exit (stragglers). A single
# run per $WORK is assumed; concurrent runs would share $WORK/bin anyway.
#
# pgrep -f matches anywhere in a command line, so a shell whose arguments merely
# mention the path (a build command, a tail, the test harness itself) would be a
# false positive. Keep only processes whose argv[0] is exactly the binary.
reap_stale() {
	local b p argv0
	for b in "$WORK/bin/p2p" "$WORK/bin/gost" "$WORK/bin/helper" \
		"$WORK/derper-root/usr/local/bin/derper"; do
		for p in $(pgrep -f -- "$b" 2>/dev/null); do
			argv0=$(tr '\0' '\n' <"/proc/$p/cmdline" 2>/dev/null | head -1)
			[ "$argv0" = "$b" ] || continue
			kill "$p" 2>/dev/null || true
		done
	done
}

# --- waiting -----------------------------------------------------------------

# wait_log <file> <ere> [timeout-seconds]
wait_log() {
	local f=$1 pat=$2 t=${3:-15}
	local i
	for i in $(seq 1 $((t * 10))); do
		grep -qE "$pat" "$f" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# wait_tcp <ns|-> <host> <port> [timeout-seconds]
wait_tcp() {
	local ns=$1 h=$2 p=$3 t=${4:-15}
	local i
	for i in $(seq 1 $((t * 10))); do
		if [ "$ns" = "-" ]; then
			timeout 1 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null && return 0
		else
			ns_run "$ns" timeout 1 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null && return 0
		fi
		sleep 0.1
	done
	return 1
}

# --- netns topology ----------------------------------------------------------
# One bridge in the root namespace with the relay (if any) and a helper echo
# server; each host gets a veth into its own namespace. Both hosts share the
# 10.99.0.0/24 L2, so hole-punched candidates are directly reachable -- the
# punch mechanism and direct-path selection are exercised, but not NAT
# translation (a CGNAT model needs a router namespace and is out of scope).

BRIDGE=p2p-e2e-br
NET_CIDR=10.99.0.0/24
NET_GW=10.99.0.1
DERP_IP=10.99.0.254
HOST_A_IP=10.99.0.2
HOST_B_IP=10.99.0.3

# net_teardown: remove everything setup_net created. Safe to call when nothing
# exists, and called first so a crashed previous run cannot poison this one.
net_teardown() {
	local n v
	for n in A B; do ip netns del "$n" 2>/dev/null || true; done
	for v in v-A vp-A v-B vp-B; do ip link del "$v" 2>/dev/null || true; done
	ip link del "$BRIDGE" 2>/dev/null || true
}

net_bridge_up() {
	ip link add "$BRIDGE" type bridge 2>/dev/null || true
	ip addr add "$NET_GW/24" dev "$BRIDGE" 2>/dev/null || true
	# The relay binds its specific address, so it must be assigned here.
	ip addr add "$DERP_IP/24" dev "$BRIDGE" 2>/dev/null || true
	ip link set "$BRIDGE" up
}

# net_host_up <ns> <ip>: veth from bridge into the namespace, address + default
# route. The parent-side veth joins the bridge.
net_host_up() {
	local n=$1 ip=$2
	local veth="v-$n" peer="vp-$n"
	ip link add "$veth" type veth peer name "$peer"
	ip link set "$veth" master "$BRIDGE"
	ip link set "$veth" up
	if [ "$NS_MODE" = ip ]; then
		ip link set "$peer" netns "$n"
		ip -n "$n" link set "$peer" name eth0
		ip -n "$n" addr add "$ip/24" dev eth0
		ip -n "$n" link set eth0 up
		ip -n "$n" route add default via "$NET_GW"
	else
		ip link set "$peer" netns "${NS_PID[$n]}"
		ns_run "$n" ip link set "$peer" name eth0
		ns_run "$n" ip addr add "$ip/24" dev eth0
		ns_run "$n" ip link set eth0 up
		ns_run "$n" ip route add default via "$NET_GW"
	fi
}

# --- curl helpers ------------------------------------------------------------

# curl_proxy <ns|-> <proxy-url> <target-url> [max-time]
curl_proxy() {
	local ns=$1 proxy=$2 target=$3 t=${4:-10}
	local out
	if [ "$ns" = "-" ]; then
		out=$(curl -s --max-time "$t" -x "$proxy" "$target" 2>/dev/null) || true
	else
		out=$(ns_run "$ns" curl -s --max-time "$t" -x "$proxy" "$target" 2>/dev/null) || true
	fi
	printf '%s' "$out"
}
