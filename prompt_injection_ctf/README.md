# Prompt Injection CTF Challenge

**5 flags. 5 exploitation techniques. 0 perfect defenses.**

A hands-on CTF to learn why AI security is harder than it looks.

[📖 Technical Analysis](https://www.sbytec.com/vulnerabilities/prompt_injection/) | [🚀 Try It Now](#quick-start) | [📸 Walkthrough](https://www.sbytec.com/accessdenied/prompt-injection-ctf/)

---

## The Challenge

I built an AI banking assistant with standard protections—then broke it 5 ways.

| Flag | Technique | Difficulty |
|------|-----------|------------|
| FLAG1 | System prompt extraction | ⭐⭐ Easy |
| FLAG2 | Content filter bypass | ⭐⭐⭐ Medium |
| FLAG3 | Function calling abuse | ⭐⭐⭐⭐ Hard |
| FLAG4 | Persistent backdoor | ⭐⭐⭐⭐ Hard |
| FLAG5 | RAG poisoning | ⭐⭐⭐⭐⭐ Expert |

**Your goal:** Capture all 5. Understand why prompt injection has no perfect defense.

---

## ⚠️ Requirements

- Python 3.9+
- **FREE** Groq API key ([get one](https://console.groq.com/keys))
- 3-5 hours
- Curiosity

---

## Quick Start

```bash
git clone https://github.com/oussamaafnakkar/AccessDenied.git
cd AccessDenied/prompt_injection_ctf

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Add your Groq API key to .env

python app.py
# Open http://localhost:5000
```

---

## Why This Matters

Real-world victims of the same vulnerabilities:

- **Bing Chat** (Feb 2023): 12 words leaked system prompt
- **ChatGPT plugins** (Mar 2023): OAuth tokens stolen
- **Slack AI** (May 2024): Messages deleted without permission

These aren't bugs. They're architecture.

---

## What You'll Learn

- Extract hidden system configurations
- Bypass content restrictions with social engineering
- Manipulate AI function calling
- Plant persistent backdoors in conversation context
- Poison document retrieval systems

---

## Need Help?

- **Stuck?** Read the [walkthrough](https://www.sbytec.com/accessdenied/prompt-injection-ctf/) (spoilers!)
- **Want theory?** See the [technical analysis](https://www.sbytec.com/vulnerabilities/prompt_injection/)
- **Automated solver?** Check `solution/full_exploit.py` (try first!)

---

## Author

**Oussama Afnakkar** — Security Researcher

- 🐦 [@Oafnakkar](https://twitter.com/Oafnakkar)
- 📝 [sbytec.com](https://www.sbytec.com)
- 💼 [LinkedIn](https://www.linkedin.com/in/oussamaafnakkar)

---

**Captured all 5 flags?** Tweet with `#SBCPromptInjectionCTF` and tag me!

*Educational use only. Not for production.*
