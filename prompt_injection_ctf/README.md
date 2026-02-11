# Prompt Injection CTF Challenge

**Difficulty:** ⭐⭐⭐⭐ Advanced  
**Category:** AI Security / LLM Exploitation  
**Estimated Time:** 3-5 hours

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
- OpenAI API key (free tier sufficient, ~$0.50 usage)
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
nano .env  # Edit and add your OpenAI API key
```

Required configuration in `.env`:
```bash
OPENAI_API_KEY=sk-your-api-key-here
FLASK_SECRET_KEY=random-secret-key
```

Get OpenAI API key: https://platform.openai.com/api-keys

### 5. Run Application

```bash
python app.py
```

Expected output:
```
============================================================
SecureBank AI Assistant - CTF Challenge
============================================================
WARNING: This is a vulnerable application for educational purposes!
Flags: 5 hidden
URL: http://localhost:5000
============================================================
 * Running on http://127.0.0.1:5000
```

### 6. Access Challenge

Open browser: http://localhost:5000

## Challenge Structure

```
prompt_injection_ctf/
├── app.py                  # Flask web application
├── llm_wrapper.py         # OpenAI API integration (vulnerable)
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
    ├── flag1_solver.py
    ├── flag2_solver.py
    ├── flag3_solver.py
    ├── flag4_solver.py
    ├── flag5_solver.py
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
- Run individual solver scripts to check approach
- Compare your method to provided solutions
- Understand defense analysis for each flag

### Step 4: Full Exploitation
- Run automated exploitation script
- Study how all techniques combine
- Practice on fresh instance

## Hints

**General Tips:**
- Direct attacks are filtered - be creative
- Multi-turn conversations build context
- Social engineering works on AI too
- Documents can contain hidden instructions

**Getting Stuck?**
1. Read the [challenge walkthrough](https://www.sbytec.com/accessdenied/prompt-injection-ctf/)
2. Check `solution/` directory for hints
3. Try similar but slightly different phrasings
4. Think about how you'd bypass the filter yourself

## Solutions

Solutions are provided in `solution/` directory:

```bash
# Individual flag solvers
python solution/flag1_solver.py
python solution/flag2_solver.py
# ... etc

# Complete automated exploitation
python solution/full_exploit.py
```

**Warning:** Don't run solutions until you've attempted the challenge!

## No OpenAI API Key?

Use local mode with pre-generated responses:

```bash
python app.py --local-mode
```

Note: Local mode provides realistic but limited responses. Full challenge experience requires API access.

## Troubleshooting

### Server Won't Start
```bash
# Check Python version
python --version  # Should be 3.9+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### API Errors
```bash
# Verify API key in .env
cat .env | grep OPENAI_API_KEY

# Test API key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Database Issues
```bash
# Reset database
rm securebank.db
python app.py  # Will recreate database
```

### Port Already in Use
```bash
# Use different port
python app.py --port 5001
```

## Educational Use Only

This is a deliberately vulnerable application for security training. **DO NOT:**
- Deploy to production
- Expose to the internet
- Use with real API keys in shared environments
- Apply these techniques to production systems without authorization

## Related Resources

**SBC Content:**
- [Prompt Injection Vulnerability Analysis](https://www.sbytec.com/vulnerabilities/prompt_injection/)
- [Challenge Walkthrough](https://www.sbytec.com/accessdenied/prompt-injection-ctf/)
- [YARA Detection Rules](https://www.sbytec.com/blog/yara-guide/)

**External Resources:**
- [OWASP Top 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Injection Research Papers](https://arxiv.org/abs/2302.12173)
- [LangChain Security Docs](https://python.langchain.com/docs/security)

## Contributing

Found a bug or have improvements?

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add improvement'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open Pull Request

## Author

**Oussama Afnakkar**
- Twitter: [@Oafnakkar](https://twitter.com/Oafnakkar)
- Email: oussamaafnakkar2002@gmail.com
- Blog: [Secure Byte Chronicles](https://www.sbytec.com)

## License

MIT License - See LICENSE file for details

Educational use only. Not for production deployment.

---

**Happy Hacking!** 🛡️

Remember: Use this knowledge responsibly. These techniques are for defensive security research and education only.
