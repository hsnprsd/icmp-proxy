#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./run_e2e_tests.sh [all|local|external] [-- <extra pytest args>]

Examples:
  ./run_e2e_tests.sh
  ./run_e2e_tests.sh local
  ./run_e2e_tests.sh external -- -q -s
USAGE
}

mode="all"
if [[ $# -gt 0 ]]; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    all|local|external)
      mode="$1"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 && "$1" == "--" ]]; then
  shift
fi

case "$mode" in
  all)
    marker='(e2e_local or e2e_external) and requires_root'
    ;;
  local)
    marker='e2e_local and requires_root'
    ;;
  external)
    marker='e2e_external and requires_root'
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ $EUID -eq 0 ]]; then
  sudo_cmd=()
else
  sudo_cmd=(sudo -E)
fi

original_icmp_ignore="$(${sudo_cmd[@]} sysctl -n net.ipv4.icmp_echo_ignore_all)"

cleanup() {
  "${sudo_cmd[@]}" sysctl -w "net.ipv4.icmp_echo_ignore_all=${original_icmp_ignore}" >/dev/null
}
trap cleanup EXIT

"${sudo_cmd[@]}" sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null
"${sudo_cmd[@]}" python3 -m pytest -m "$marker" "$@"
