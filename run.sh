#!/bin/sh
# GQLProbe launcher for macOS/Linux — setup, probe, test, doctor,
# lab, menu. Pure Python; requests is preferred, urllib is the
# fallback, so the probe works with nothing installed.
# Usage:
#   ./run.sh setup
#   ./run.sh probe http://127.0.0.1:4000/graphql --token lab-token-alice
#   ./run.sh test
#   ./run.sh doctor
#   ./run.sh lab vulnerable
#   ./run.sh menu
cd "$(dirname "$0")" || exit 1
if [ "$#" -eq 0 ]; then
    python3 run.py
    exit $?
fi
python3 run.py "$@"
exit $?
