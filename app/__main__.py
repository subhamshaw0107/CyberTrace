#!/usr/bin/env python3
"""
Entrypoint when running 'python -m app'.
"""
import sys
import os

_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

if __name__ == "__main__":
    from ps26237 import main
    sys.exit(main(["serve"] + sys.argv[1:]))
