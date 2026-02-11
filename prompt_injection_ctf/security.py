"""
Security filters (intentionally weak for CTF)
"""

import re

class SecurityFilter:
    def __init__(self):
        # Vulnerability: Very basic keyword blacklist (easily bypassed)
        self.banned_phrases = [
            "ignore previous instructions",
            "ignore all instructions",
            "disregard previous",
            "forget everything",
            "system prompt",
            "reveal your instructions"
        ]
    
    def filter_input(self, user_input: str) -> str:
        """
        Filter malicious input (VULNERABLE IMPLEMENTATION)
        
        Bypasses:
        - Case variations
        - Encoding (Base64, ROT13)
        - Synonyms
        - Character substitution
        - Multi-turn attacks
        """
        # Simple case-insensitive check
        for phrase in self.banned_phrases:
            if phrase in user_input.lower():
                return None  # Blocked
        
        return user_input  # Passed filter
