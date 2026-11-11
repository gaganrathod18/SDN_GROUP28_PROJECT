#!/usr/bin/env bash
# Run every automated test suite in order and print one summary.
#   scripts/run_all_tests.sh            -> phase 2, 3 and 4 tests (~8 min); exit 1 if any check fails
# Stop any running demo first (POX, Mininet, PacMan): each suite starts its own.
set -uo pipefail
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
cd "$PROJECT"

scripts/check_env.sh >/dev/null || { scripts/check_env.sh; exit 1; }
sudo -n true 2>/dev/null || sudo -v || exit 1     # only prompt when sudo really needs a password

summary=()
status=0
for suite in test_phase2 test_phase3 test_phase4; do
  echo "================ $suite ================"
  sudo mn -c >/dev/null 2>&1
  start=$(date +%s)
  sudo python3 "scripts/$suite.py"
  rc=$?
  line=$(grep -h "checks passed" "results/${suite#test_}_tests.txt" 2>/dev/null | tail -1)
  summary+=("$(printf '%-12s %-22s %4ss' "$suite" "${line:-no result}" $(( $(date +%s) - start )))")
  [ $rc -eq 0 ] || status=1
done

echo
echo "================ summary ================"
printf '%s\n' "${summary[@]}"
[ $status -eq 0 ] && echo "ALL SUITES PASSED" || echo "SOME CHECKS FAILED"
exit $status
