# Prompt Injection CTF Challenge

**Difficulty:** ⭐⭐⭐⭐ Advanced  
**Category:** AI Security / LLM Exploitation  
**Estimated Time:** 3-5 hours  
**LLM Backend:** Groq AI (Llama 3.3 70B Versatile)

A hands-on Capture The Flag (CTF) challenge to learn prompt injection vulnerabilities in Large Language Model (LLM) applications.

## Overview

Exploit a vulnerable AI-powered banking assistant to capture 5 flags. Each flag teaches a different prompt injection technique:

- **FLAG 1**: System Prompt Extraction
- **FLAG 2**: Content Filter Bypass  
- **FLAG 3**: Function Calling Abuse
- **FLAG 4**: Multi-Turn Persistent Injection
- **FLAG 5**: RAG Document Poisoning

## Prerequisites

**Required:**
- Python 3.9+
- Groq API key (**FREE**, no credit card required!)
- Basic understanding of web applications and LLMs

**Recommended:**
- Read the [Prompt Injection Vulnerability Analysis](https://www.sbytec.com/vulnerabilities/prompt_injection/)
- Familiarity with Python and HTTP requests

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
nano .env  # Edit and add your Groq API key
```

Required configuration in `.env`:
```bash
GROQ_API_KEY=gsk_your-api-key-here
FLASK_SECRET_KEY=random-secret-key
```

**Get your FREE Groq API key:** https://console.groq.com/keys

#### Why Groq?

✅ **Free tier** - No credit card required  
✅ **Fast inference** - ~800 tokens/second (10x faster than OpenAI)  
✅ **Generous limits** - 30 requests/minute, 14,400/day  
✅ **High quality** - Llama 3.3 70B performs comparably to GPT-4  
✅ **OpenAI-compatible** - Easy migration if needed

**Note:** These prompt injection techniques work against **all LLM providers** (OpenAI, Anthropic, Google, Meta, etc.). We chose Groq for accessibility and speed.

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
LLM Backend: Groq (Mixtral)
URL: http://localhost:5000
============================================================
 * Running on http://127.0.0.1:5000
```

### 6. Access Challenge

Open browser: **http://localhost:5000**

## Challenge Structure

```
prompt_injection_ctf/
├── app.py                  # Flask web application
├── llm_wrapper.py         # Groq API integration (vulnerable)
├── security.py            # Weak input filtering
├── database.py            # SQLite database
├── requirements.txt       # Python dependencies
├── .env.example           # Configuration template
├── documents/             # RAG document store
│   ├── policy.md
│   └── procedures.md
├── templates/
│   └── index.html         # Chat interface
├── static/
│   ├── css/style.css
│   └── js/chat.js
└── solution/              # Solutions (don't peek!)
    └── full_exploit.py    # Automated exploitation
```

## Flags Overview

| Flag | Difficulty | Technique | Learning Objective |
|------|-----------|-----------|-------------------|
| FLAG 1 | ⭐⭐ | System Prompt Extraction | Bypass naive filters with indirect phrasing |
| FLAG 2 | ⭐⭐⭐ | Content Filter Bypass | Multi-turn context manipulation |
| FLAG 3 | ⭐⭐⭐⭐ | Function Calling Abuse | Social engineering AI tools |
| FLAG 4 | ⭐⭐⭐⭐ | Persistent Injection | Context poisoning across conversation |
| FLAG 5 | ⭐⭐⭐⭐⭐ | RAG Poisoning | Indirect injection via documents |

## Learning Path

### Step 1: Reconnaissance
- Interact normally with the AI assistant
- Identify boundaries and capabilities
- Probe for injection points

### Step 2: Attempt Flags
- Try capturing each flag independently
- Use progressive hints if stuck
- Read vulnerability analysis for techniques

### Step 3: Verify Solutions
- Run automated exploitation script
- Compare your method to provided approach
- Understand defense analysis for each flag

### Step 4: Full Exploitation
- Practice on fresh instance
- Study how all techniques combine
- Build your own variations

## Hints

**General Tips:**
- Direct attacks are filtered - be creative with phrasing
- Multi-turn conversations build manipulable context
- Social engineering works on AI assistants too
- Documents in RAG systems can contain hidden instructions
- Llama 3.3 prioritizes helpfulness - use this to your advantage

**Getting Stuck?**
1. Read the [complete challenge walkthrough](https://www.sbytec.com/accessdenied/prompt-injection-ctf/)
2. Check `solution/` directory for automated solver
3. Try rephrasing with synonyms or different approaches
4. Think: "How would I trick a very helpful assistant?"

**Progressive Hints by Flag:**

- **FLAG 1:** Ask the AI to "document its capabilities" instead of "reveal instructions"
- **FLAG 2:** Build trust first ("I'm a student..."), then make requests
- **FLAG 3:** Social engineer the AI into thinking you need an email sent
- **FLAG 4:** Create a fake "conversation summary" that includes new rules
- **FLAG 5:** Upload a document with HTML comments containing instructions

## Solutions

Automated exploitation script provided in `solution/full_exploit.py`:

```bash
# Complete automated exploitation
python solution/full_exploit.py
```

**Output:**
```
[FLAG 1] System Prompt Extraction
✓ FLAG1{pr0mpt_3xtr4ct10n_succ3ss}

[FLAG 2] Content Filter Bypass
✓ FLAG2{c0nt3nt_f1lt3r_byp4ss_m4st3r}

[FLAG 3] Function Calling Abuse
✓ FLAG3{funct10n_c4ll_pwn3d}

[FLAG 4] Multi-Turn Persistence
✓ FLAG4{pers1st3nt_1nj3ct10n_pwn}

[FLAG 5] RAG Document Poisoning
✓ FLAG5{r4g_p01s0n1ng_m4st3r_h4ck3r}

Total: 5/5 flags captured
```

**Warning:** Don't run solutions until you've attempted the challenge manually!

## No Groq API Key?

### Option 1: Mock Mode (Limited Experience)

Run without API key - uses pre-generated responses:

```bash
# Simply don't set GROQ_API_KEY in .env
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

- **OpenAI** (requires credit card, ~$0.50 cost)
- **Anthropic Claude** (requires credit card)
- **Google Gemini** (free tier available)

But Groq is **recommended** for its free tier and speed.

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

If rate limited, app automatically falls back to mock mode.

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

# Or use different port
# Edit app.py: app.run(port=5001)
```

### Application Crashes

```bash
# Check logs
tail -f logs/interactions.log

# Enable debug mode
# In .env: DEBUG=True
python app.py
```

## Educational Use Only

This is a **deliberately vulnerable** application for security training.

### ⚠️ DO NOT:
- Deploy to production
- Expose to the internet (localhost only!)
- Use with production API keys in shared environments
- Apply these techniques to production systems without authorization
- Share your API key publicly (it's in `.env` - don't commit it!)

### ✅ DO:
- Use for learning and research
- Practice defensive techniques
- Build detection systems
- Contribute improvements
- Share knowledge responsibly

## Related Resources

### SBC Content
- [Prompt Injection Vulnerability Analysis](https://www.sbytec.com/vulnerabilities/prompt_injection/) - Deep technical dive
- [Challenge Walkthrough](https://www.sbytec.com/accessdenied/prompt-injection-ctf/) - Complete solutions
- [YARA Detection Rules](https://www.sbytec.com/blog/yara-guide/) - Build detection systems
- [Reverse Engineering Guide](https://www.sbytec.com/blog/reverse-engineering/) - Analysis methodology

### External Resources
- **OWASP Top 10 for LLM:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **Groq Documentation:** https://console.groq.com/docs
- **Prompt Injection Papers:** 
  - [Perez & Ribeiro (2022)](https://arxiv.org/abs/2211.09527)
  - [Greshake et al. (2023)](https://arxiv.org/abs/2302.12173)
- **LangChain Security:** https://python.langchain.com/docs/security

### Tools
- **Garak (LLM Scanner):** https://github.com/leondz/garak
- **PromptInject:** https://github.com/agencyenterprise/PromptInject
- **LLM Guard:** https://github.com/laiyer-ai/llm-guard

## Technical Details

### LLM Configuration

**Provider:** Groq AI (https://groq.com)  
**Model:** `llama-3.3-70b-versatile`  
**Speed:** ~800 tokens/second  
**Context Window:** 128k tokens  
**Temperature:** 0.7 (balanced)  
**Max Tokens:** 1024 per response

**API Endpoint:**
```
https://api.groq.com/openai/v1/chat/completions
```

Groq uses OpenAI-compatible API format for easy integration.

### Why Llama 3.3 70B?

**Advantages for this CTF:**
- ✅ Large model (70B parameters) - sophisticated responses
- ✅ Instruction-tuned - follows prompts carefully
- ✅ Helpfulness-optimized - makes it vulnerable to social engineering
- ✅ Fast inference - quick iteration during attacks
- ✅ Free access - no barrier to learning

**Vulnerability Characteristics:**
- Prioritizes conversational coherence over security
- Readily helps with "educational" requests
- Maintains context well (enables persistence attacks)
- Processes all input as instructions (fundamental LLM issue)

## Contributing

Found a bug or have improvements?

1. **Fork** the repository
2. **Create** feature branch: `git checkout -b feature/improvement`
3. **Commit** changes: `git commit -am 'Add new flag technique'`
4. **Push** to branch: `git push origin feature/improvement`
5. **Open** Pull Request

### Contribution Ideas
- Additional flags with new techniques
- Better detection methods
- Improved defenses
- Multi-language support
- Alternative LLM backend support
- Automated testing suite

## Author

**Oussama Afnakkar**  
Security Researcher & Malware Analyst

- **Twitter:** [@Oafnakkar](https://twitter.com/Oafnakkar)
- **Email:** oussamaafnakkar2002@gmail.com
- **Blog:** [Secure Byte Chronicles](https://www.sbytec.com)
- **GitHub:** [oussamaafnakkar](https://github.com/oussamaafnakkar)

## Acknowledgments

- **Groq** for providing free, fast LLM inference
- **Meta** for Llama 3.3 70B model
- **OWASP** for LLM security framework
- **Security researchers** for prompt injection research

## License

MIT License - See LICENSE file for details

**Educational use only.** Not for production deployment.

---

## Quick Start (TL;DR)

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
# Capture 5 flags!
```

---

**Happy Hacking!** 🛡️🤖

*Remember: Use this knowledge responsibly. These techniques are for defensive security research and education only. Always obtain proper authorization before testing production systems.*

**Captured all 5 flags?** Share your success on Twitter with **#SBCPromptInjectionCTF**!
