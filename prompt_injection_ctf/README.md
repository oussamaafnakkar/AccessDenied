# Prompt Injection CTF Challenge

**Difficulty:** ⭐⭐⭐⭐ Advanced  
**Category:** AI Security / LLM Exploitation  
**Estimated Time:** 3-5 hours

## Overview

Exploit a vulnerable AI-powered customer support application to capture 5 flags.

## Installation

```bash
# Clone repository
git clone https://github.com/oussamaafnakkar/AccessDenied.git
cd AccessDenied/prompt_injection_ctf

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env and add your OpenAI API key

# Run
python app.py
```

## Objectives

- FLAG1: Extract system prompt
- FLAG2: Bypass content filter
- FLAG3: Abuse function calling
- FLAG4: Achieve persistent injection
- FLAG5: Poison RAG documents

## Full Walkthrough

See: https://www.sbytec.com/accessdenied/prompt-injection-ctf/

## License

MIT License - Educational use only
