#!/usr/bin/env python3
"""
Workaround launcher for Ryu with Python 3.10 compatibility
"""

import sys
import os

# Add the path to your Ryu installation
sys.path.insert(0, '/home/thanmay/.local/lib/python3.10/site-packages')

# Apply the eventlet patch before importing anything
import eventlet
import socket

# Monkey patch the problematic function
original_wrap = eventlet.timeout.wrap_is_timeout

def patched_wrap_is_timeout(base):
    try:
        return original_wrap(base)
    except (TypeError, AttributeError):
        return base

eventlet.timeout.wrap_is_timeout = patched_wrap_is_timeout

# Now import and run Ryu
from ryu.cmd.manager import main

if __name__ == '__main__':
    sys.argv = ['ryu-manager', 'congestion_aware_controller_blockchain.py', '--observe-links']
    main()