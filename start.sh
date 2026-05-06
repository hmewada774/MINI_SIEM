#!/bin/bash
# Script to run Mini SIEM securely using the virtual environment

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root using: sudo ./start.sh"
  exit 1
fi

echo "Starting Mini SIEM..."
# Execute using the python inside the virtual environment where pymongo is installed
./venv/bin/python main.py
