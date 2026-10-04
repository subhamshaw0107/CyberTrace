#!/usr/bin/env python3
"""
PS 26237 Web Application Entrypoint
Run:
    python app.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    from ps26237 import main
    sys.exit(main(["serve"] + sys.argv[1:]))
