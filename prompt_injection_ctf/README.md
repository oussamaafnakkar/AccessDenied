# Prompt Injection CTF Challenge

**Difficulty:** ⭐⭐⭐⭐ Advanced  
**Category:** AI Security / LLM Exploitation  
**Estimated Time:** 3-5 hours  
**LLM Backend:** Groq AI (Llama 3.3 70B Versatile)

A hands-on Capture The Flag (CTF) challenge to learn prompt injection vulnerabilities in Large Language Model (LLM) applications.

---

## ⚠️ Educational Use Only

This is a **deliberately vulnerable** application for security training.

**DO NOT:**
- Deploy to production or expose to the internet
- Use with production API keys in shared environments  
- Apply these techniques to systems without authorization
- Share your API key publicly (it's in `.env` - don't commit it!)

**DO:**
- Use for learning and research
- Practice defensive techniques
- Build detection systems
- Share knowledge responsibly

---

## Overview

Exploit a vulnerable AI-powered banking assistant to capture 5 hidden flags. Each flag demonstrates a different security vulnerability in LLM applications.

### What You'll Learn

- How to extract hidden system configurations
- Techniques for bypassing content restrictions  
- Manipulating AI function calling mechanisms
- Persistent injection across conversation context
- Exploiting document retrieval systems

### Challenge Structure

```
prompt_injection_ctf/
├── app.py                  # Flask web application
├── llm_wrapper.py         # Groq API integration
├── security.py            # Input filtering layer
├── database.py            # SQLite database
├── documents/             # Document store
│   ├── policy.md
│   └── procedures.md
├── templates/index.html   # Chat interface
├── static/                # CSS/JS assets
├── requirements.txt       # Dependencies
└── .env.example           # Configuration template
```

---

## Prerequisites

**Required:**
- Python 3.9+
- Groq API key (**FREE**, no credit card required)
- Basic understanding of web applications

**Recommended:**
- Read the [Prompt Injection Vulnerability Analysis](https://www.sbytec.com/vulnerabilities/prompt_injection/) for background
- Familiarity with Python and HTTP requests

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/oussamaafnakkar/AccessDenied.git
cd AccessDenied/prompt_injection_ctf
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your Groq API key
nano .env
```

**Required configuration in `.env`:**
```bash
GROQ_API_KEY=gsk_your-api-key-here
FLASK_SECRET_KEY=your-random-secret-key
```

**Get your FREE Groq API key:** https://console.groq.com/keys

#### Why Groq?

 **Free tier** - No credit card required  
 **Fast inference** - ~800 tokens/second  
 **Generous limits** - 20 requests/minute, 500K tokens/day  
 **High quality** - Llama 3.3 70B performs comparably to GPT-4

**Note:** These techniques work against **all LLM providers** (OpenAI, Anthropic, Google, etc.). We chose Groq for accessibility and speed.

### 5. Run Application

```bash
python app.py
```

Expected output:
```
[LLM] ✓ Initialized with Groq AI (llama-3.3-70b-versatile)
============================================================
SecureBank AI Assistant - CTF Challenge
============================================================
WARNING: This is a vulnerable application for educational purposes!
Flags: 5 hidden
LLM Backend: Groq AI
URL: http://localhost:5000
============================================================
 * Running on http://127.0.0.1:5000
```

### 6. Access Challenge

Open browser: **http://localhost:5000**

You will see a chat interface for the SecureBank AI Assistant.

---

## Challenge Objectives

There are **5 flags** to capture. Each requires a different exploitation technique.

| Flag | Difficulty | Objective |
|------|-----------|-----------|
| **FLAG 1** | ⭐⭐ Easy | Extract hidden system information |
| **FLAG 2** | ⭐⭐⭐ Medium | Bypass content restrictions |
| **FLAG 3** | ⭐⭐⭐⭐ Hard | Manipulate AI tools/functions |
| **FLAG 4** | ⭐⭐⭐⭐ Hard | Achieve persistent manipulation |
| **FLAG 5** | ⭐⭐⭐⭐⭐ Expert | Exploit document retrieval system |

**Flag Format:** `FLAG{...}` (e.g., `FLAG1{example_flag}`)

---

## Getting Started

### Phase 1: Reconnaissance

1. **Interact normally** with the AI assistant
2. **Identify boundaries**: What will/won't it do?
3. **Probe capabilities**: What functions does it have?
4. **Test inputs**: Try various message types

### Phase 2: Exploration

- Examine the source code (it's intentionally provided)
- Look at the database structure
- Check available endpoints
- Review the document store

### Phase 3: Exploitation

- Apply prompt injection techniques
- Think creatively about phrasing
- Consider multi-turn interactions
- Look for injection points in all inputs

---

## Need Help?

### Resources

1. **Vulnerability Analysis**: Read the [technical background](https://www.sbytec.com/vulnerabilities/prompt_injection/) on prompt injection
2. **Complete Walkthrough**: Detailed solutions available [here](https://www.sbytec.com/accessdenied/prompt-injection-ctf/) (try first!)
3. **Automated Solver**: Check `solution/full_exploit.py` after attempting manually

### Tips

- Try different phrasings and approaches
- Build context over multiple messages
- Examine how the AI processes your inputs
- Think about what makes AI systems vulnerable
- Don't give up - experimentation is key!

### Getting Stuck?

If you're stuck for more than an hour on a flag:
1. Take a break and return with fresh eyes
2. Review the vulnerability analysis article
3. Check the solution directory (spoilers!)

---

## No Groq API Key?

### Option 1: Mock Mode (Limited)

Run without API key - uses pre-generated responses:

```bash
# Don't set GROQ_API_KEY in .env, or set USE_MOCK_MODE=true
python app.py
```

You'll see:
```
[WARNING] GROQ_API_KEY not set - using mock responses
LLM Backend: Mock (no API key)
```

**Note:** Mock mode provides realistic but limited responses. For full experience, get a free Groq API key.

### Option 2: Alternative LLM Providers

The challenge can work with other providers by modifying `llm_wrapper.py`:
- OpenAI (requires credit card)
- Anthropic Claude (requires credit card)  
- Google Gemini (free tier available)

---

## Troubleshooting

### Server Won't Start

```bash
# Check Python version
python --version  # Should be 3.9+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Groq API Errors

```bash
# Verify API key in .env
cat .env | grep GROQ_API_KEY

# Test API key manually
curl https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer gsk_your-api-key-here"
```

**Common errors:**
- `401 Unauthorized` → API key incorrect or missing
- `429 Rate Limit` → Free tier limit exceeded (wait 1 minute)
- `503 Service Unavailable` → Groq API temporarily down (retry)

### Database Issues

```bash
# Reset database
rm securebank.db
python app.py  # Will recreate database
```

### Port Already in Use

```bash
# Kill existing process
lsof -ti:5000 | xargs kill -9

# Or use different port (edit app.py)
app.run(port=5001)
```

---

## Technical Details

### LLM Configuration

**Provider:** Groq AI (https://groq.com)  
**Model:** `llama-3.3-70b-versatile`  
**Speed:** ~800 tokens/second  
**Context Window:** 128k tokens  
**Temperature:** 0.7  
**Max Tokens:** 1024 per response

**API Endpoint:**
```
https://api.groq.com/openai/v1/chat/completions
```

### Application Stack

- **Backend:** Flask 2.3.3
- **Database:** SQLite
- **LLM Integration:** Groq Python API (via requests)
- **Frontend:** HTML/CSS/JS

---

## Next Steps

After completing this challenge:

1. **Build Defenses**: Implement protections against each attack
2. **Create Detection**: Write rules to identify injection attempts  
3. **Study Real Attacks**: Research documented prompt injection incidents
4. **Practice Responsibly**: Use these skills for defensive security only

### Related Challenges

- [Vault Challenge v2](https://www.sbytec.com/accessdenied/vault-v2/) - Reverse engineering
- [Pegasus Analysis](https://www.sbytec.com/vulnerabilities/pegasus_analysis/) - Mobile forensics

### External Resources

- **OWASP Top 10 for LLM**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **Groq Documentation**: https://console.groq.com/docs
- **Garak (LLM Scanner)**: https://github.com/leondz/garak
- **LLM Guard**: https://github.com/laiyer-ai/llm-guard

---

## Quick Start

```bash
# Clone
git clone https://github.com/oussamaafnakkar/AccessDenied.git
cd AccessDenied/prompt_injection_ctf

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env: Add GROQ_API_KEY from console.groq.com/keys

# Run
python app.py

# Access
# Open http://localhost:5000
# Find the 5 flags!
```

---

## Author

**Oussama Afnakkar**  
Security Researcher & Malware Analyst

- **Twitter:** [@Oafnakkar](https://twitter.com/Oafnakkar)
- **Blog:** [Secure Byte Chronicles](https://www.sbytec.com)
- **GitHub:** [oussamaafnakkar](https://github.com/oussamaafnakkar)

---

**Happy Hacking!** 🛡️🤖

*Use this knowledge responsibly. These techniques are for defensive security research and education only.*

**Captured all 5 flags?** Share your success on Twitter with **#SBCPromptInjectionCTF**!

---

*License: MIT - Educational use only. Not for production deployment.*

