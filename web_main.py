#!/usr/bin/env python3
"""
Web GUI Entry Point for File Encryption Tool.

Run this file to start the web-based GUI application.
The application will open in your default web browser at http://127.0.0.1:8000
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.web.app import run_app

if __name__ == "__main__":
    # Run the web application (port 8000 to avoid conflict with Apple AirPlay on port 5000)
    run_app(debug=False, port=8000)
