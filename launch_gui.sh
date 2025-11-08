#!/bin/bash
# Simple launcher script for the GUI
# Just run: ./launch_gui.sh

cd "$(dirname "$0")"
source venv/bin/activate
./venv/bin/python3 gui_main.py
