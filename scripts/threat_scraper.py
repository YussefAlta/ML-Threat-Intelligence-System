#!/usr/bin/env python3
"""
Entry point script for Threat Intelligence Web Scraper
"""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from threat_intelligence.main import main

if __name__ == "__main__":
    sys.exit(main())
