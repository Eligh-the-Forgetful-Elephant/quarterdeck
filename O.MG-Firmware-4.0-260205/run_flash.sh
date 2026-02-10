#!/usr/bin/env bash
# Run O.MG flash.py with the correct Python environment (pyserial).
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "Creating virtual environment and installing pyserial..."
  python3 -m venv .venv
  .venv/bin/pip install pyserial
fi

exec .venv/bin/python3 flash.py "$@"
