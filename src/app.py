"""
=====================================================================
 Implementation of NIST Security Standards Using Cryptographic
 Algorithms
=====================================================================
 Student   : Tahniat Farhan
 Reg. No   : 2025(S)-CYS-15
 Department: Cyber Security
 University: UET Lahore
 Course    : Introduction to Cyber Security / Cryptography Lab

 Backward-Compatible Entry Point Wrapper for nist_crypto package.
 Run with: python app.py
=====================================================================
"""

import sys
import os

# Add src to sys.path if invoked directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nist_crypto.cli import main

if __name__ == "__main__":
    main()
