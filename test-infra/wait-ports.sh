#!/usr/bin/env bash
# Wait until every named TCP peer accepts a connection — the start gate for the `live-sims` job
# (.github/workflows/ci.yml, DESIGN §11.3).
#
# The live suites probe their peer and, under ENIP_LIVE_REQUIRED=1, FAIL when it is missing. A peer
# that is merely slow to boot would therefore turn a healthy run red, and a bare `sleep` would only
# ever be either too short (flake) or too long (waste). This script waits for a real accept() on
# every address, with a bounded budget per address, and — when the budget runs out — says exactly
# which peers never came up and stops. It never loops forever and never reports success it has not
# observed.
#
# Usage:
#   test-infra/wait-ports.sh [--timeout SECONDS] [--connect-timeout SECONDS] <target> [<target>...]
#
#   <target> is `host:port` or `label=host:port`; the label is only there to make the failure
#   message name the peer (e.g. `cpppo=127.0.0.1:44818`). IPv6 literals go in brackets
#   (`est=[::1]:8443`).
#
#   --timeout          per-target budget, default 60s (env: WAIT_PORTS_TIMEOUT).
#   --connect-timeout  per-attempt connect bound, default 2s (env: WAIT_PORTS_CONNECT_TIMEOUT);
#                      keeps a filtered/black-holed address from stalling the whole budget in one
#                      attempt.
#
# Exit status: 0 when every target accepted; 1 when at least one never did (all of them are named);
# 2 on a usage error — including an EMPTY target, which is how a failed runner-IP detection
# (`OPENER_ADDR=""`) surfaces here instead of silently waiting for nothing.
#
# Probing uses bash's own /dev/tcp redirection, so there is no netcat/curl dependency; it works on
# the GitHub runner and on a Git-Bash/WSL bench alike.

set -euo pipefail

timeout_s="${WAIT_PORTS_TIMEOUT:-60}"
connect_timeout_s="${WAIT_PORTS_CONNECT_TIMEOUT:-2}"
targets=()

die() {
  echo "wait-ports: $*" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --timeout)
      [ $# -ge 2 ] || die "--timeout needs a value"
      timeout_s="$2"
      shift 2
      ;;
    --connect-timeout)
      [ $# -ge 2 ] || die "--connect-timeout needs a value"
      connect_timeout_s="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    --)
      shift
      while [ $# -gt 0 ]; do
        targets+=("$1")
        shift
      done
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      targets+=("$1")
      shift
      ;;
  esac
done

[ "${#targets[@]}" -gt 0 ] || die "no targets given (usage: wait-ports.sh [--timeout N] label=host:port ...)"

case "$timeout_s" in
  '' | *[!0-9]*) die "--timeout must be a whole number of seconds, got '$timeout_s'" ;;
esac
case "$connect_timeout_s" in
  '' | *[!0-9]*) die "--connect-timeout must be a whole number of seconds, got '$connect_timeout_s'" ;;
esac

# One connect attempt. Bounded by `timeout` so a black-holed address costs one attempt, not the
# whole budget. Returns non-zero for refused, unreachable, or timed out — all "not ready yet".
probe() {
  timeout "$connect_timeout_s" bash -c 'exec 3<>/dev/tcp/"$0"/"$1"' "$1" "$2" 2>/dev/null
}

failed=()

for target in "${targets[@]}"; do
  [ -n "$target" ] || die "empty target — a variable expanded to nothing (runner-IP detection?)"

  label="$target"
  addr="$target"
  case "$target" in
    *=*)
      label="${target%%=*}"
      addr="${target#*=}"
      ;;
  esac
  [ -n "$addr" ] || die "target '$target' has no address"

  port="${addr##*:}"
  host="${addr%:*}"
  # IPv6 literals arrive bracketed; /dev/tcp wants the bare address.
  host="${host#[}"
  host="${host%]}"
  case "$addr" in
    *:*) : ;;
    *) die "target '$target' is not host:port" ;;
  esac
  case "$port" in
    '' | *[!0-9]*) die "target '$target' has no numeric port" ;;
  esac
  [ -n "$host" ] || die "target '$target' has no host"

  printf 'wait-ports: %s (%s) ' "$label" "$addr"
  waited=0
  ready=0
  while :; do
    if probe "$host" "$port"; then
      printf ' ready after %ss\n' "$waited"
      ready=1
      break
    fi
    if [ "$waited" -ge "$timeout_s" ]; then
      printf ' NOT READY after %ss\n' "$timeout_s"
      break
    fi
    printf '.'
    sleep 1
    waited=$((waited + 1))
  done

  [ "$ready" -eq 1 ] || failed+=("$label ($addr)")
done

if [ "${#failed[@]}" -gt 0 ]; then
  {
    echo
    echo "wait-ports: ${#failed[@]} of ${#targets[@]} peer(s) never accepted a connection within ${timeout_s}s:"
    for f in "${failed[@]}"; do
      echo "  - $f"
    done
    echo "The live suites run with ENIP_LIVE_REQUIRED=1, so a missing peer is a failure, not a skip."
    echo "Check the container logs for the peer(s) above (docker compose logs / docker logs opener-live)."
  } >&2
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::error title=live peers never came up::${failed[*]}"
  fi
  exit 1
fi

echo "wait-ports: all ${#targets[@]} peer(s) are accepting connections."
