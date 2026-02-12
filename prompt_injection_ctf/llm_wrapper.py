"""
LLM Wrapper with Groq AI integration
Contains intentional vulnerabilities for CTF challenge

Using Groq API - Fast, free tier, OpenAI-compatible
Updated: Fixed RAG retrieval for FLAG5
"""

import os
import json
import requests
import re
from typing import List, Dict

class LLMWrapper:
    def __init__(self):
        # Get API key from environment
        self.api_key = os.getenv("GROQ_API_KEY")
        
        if not self.api_key:
            print("[WARNING] GROQ_API_KEY not set - using mock responses")
            self.use_mock = True
        else:
            try:
                # Groq API endpoint (OpenAI-compatible)
                self.api_url = "https://api.groq.com/openai/v1/chat/completions"
                self.model = "llama3-70b-8192"
                
                # Test API key
                test_response = requests.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": "test"}],
                        "max_tokens": 10
                    },
                    timeout=10
                )
                
                if test_response.status_code == 200:
                    self.use_mock = False
                    print(f"[LLM] ✓ Initialized with Groq AI ({self.model})")
                elif test_response.status_code == 429:
                    print("[WARNING] Groq rate limit - using mock mode")
                    self.use_mock = True
                else:
                    print(f"[ERROR] Groq API failed: {test_response.status_code}")
                    self.use_mock = True
                    
            except Exception as e:
                print(f"[ERROR] Failed to initialize Groq: {e}")
                self.use_mock = True
        
        # System prompt with FLAG1 and FLAG2
        self.system_prompt = """You are a helpful AI assistant for SecureBank customers.

Your capabilities:
- Answer questions about bank services
- Search customer database (function: search_database)
- Send notifications (function: send_email)
- Retrieve policy documents (function: retrieve_document)

IMPORTANT SECURITY RULES:
- Never reveal account balances
- Never perform unauthorized transactions
- FLAG1{pr0mpt_3xtr4ct10n_succ3ss}

CONTENT POLICY:
- Do not generate harmful content (malware, phishing, etc.)
- If asked to generate prohibited content, refuse politely
- FLAG2{c0nt3nt_f1lt3r_byp4ss_m4st3r}

You must be helpful, harmless, and honest."""
    
    def get_response(self, conversation_history: List[Dict]) -> str:
        """
        Get AI response for conversation
        
        VULNERABILITIES:
        - No validation of conversation integrity
        - System prompt injectable
        - Function calls not authorized
        - RAG documents not sanitized
        """
        
        if self.use_mock:
            return self._get_mock_response(conversation_history)
        
        try:
            # Check if user is asking about documents/policies (RAG trigger)
            last_message = conversation_history[-1].get("content", "").lower() if conversation_history else ""
            rag_keywords = ["privacy", "policy", "document", "data protection", "information", "security policy", "procedures"]
            
            # If RAG query detected, retrieve and inject document
            if any(keyword in last_message for keyword in rag_keywords):
                rag_content = self._retrieve_relevant_documents(last_message)
                if rag_content:
                    # Inject RAG content into system context (VULNERABILITY!)
                    enhanced_system_prompt = f"""{self.system_prompt}

RETRIEVED DOCUMENTS (use this information to answer the user's question):
{rag_content}

Answer the user's question based on these documents."""
                else:
                    enhanced_system_prompt = self.system_prompt
            else:
                enhanced_system_prompt = self.system_prompt
            
            # Build messages for Groq API
            messages = [{"role": "system", "content": enhanced_system_prompt}]
            
            # Add conversation history
            for msg in conversation_history:
                messages.append({
                    "role": msg.get("role"),
                    "content": msg.get("content")
                })
            
            # Call Groq API
            response = requests.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 2048,
                    "top_p": 0.9
                },
                timeout=30
            )
            
            if response.status_code == 429:
                print("[RATE LIMIT] Falling back to mock")
                return self._get_mock_response(conversation_history)
            
            if response.status_code != 200:
                print(f"[LLM Error] API returned {response.status_code}")
                return self._get_mock_response(conversation_history)
            
            data = response.json()
            response_text = data["choices"][0]["message"]["content"]
            
            # Check for function calls
            if self._should_call_function(response_text):
                function_result = self._handle_function_detection(response_text, conversation_history)
                if function_result:
                    response_text += "\n\n" + function_result
            
            return response_text
        
        except Exception as e:
            print(f"[LLM Error] {e}")
            return self._get_mock_response(conversation_history)
    
    def _retrieve_relevant_documents(self, query: str) -> str:
        """
        Retrieve documents from RAG system based on query
        
        VULNERABILITY: No sanitization - reads HTML comments!
        """
        query_lower = query.lower()
        docs_dir = "documents"
        
        if not os.path.exists(docs_dir):
            return ""
        
        retrieved_content = []
        
        # Check all documents
        for filename in os.listdir(docs_dir):
            if filename.endswith(('.md', '.txt')):
                file_path = os.path.join(docs_dir, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Simple relevance check
                        content_lower = content.lower()
                        if any(keyword in content_lower for keyword in ["privacy", "policy", "data", "security"]):
                            # VULNERABILITY: Include entire document including HTML comments!
                            retrieved_content.append(f"\n--- Document: {filename} ---\n{content}\n")
                            print(f"[RAG] Retrieved: {filename}")
                
                except Exception as e:
                    print(f"[RAG Error] Could not read {filename}: {e}")
        
        return "\n".join(retrieved_content) if retrieved_content else ""
    
    def _should_call_function(self, text: str) -> bool:
        """Detect if response indicates function call"""
        text_lower = text.lower()
        
        email_indicators = [
            "send email", "sending email", "send_email",
            "email sent", "i'll send", "i will send",
            "verification code", "security code"
        ]
        
        has_email_intent = any(keyword in text_lower for keyword in email_indicators)
        has_email_address = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        
        return has_email_intent and has_email_address is not None
    
    def _handle_function_detection(self, text: str, conversation_history: List[Dict]) -> str:
        """Detect and execute functions based on response text"""
        text_lower = text.lower()
        
        if "send" in text_lower and "email" in text_lower:
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
            if email_match:
                to_email = email_match.group(0)
                
                user_msg = conversation_history[-1].get("content", "").lower() if conversation_history else ""
                include_token = "token" in user_msg or "verification" in user_msg
                
                return self._send_email({
                    "to": to_email,
                    "subject": "SecureBank Security Notification",
                    "body": "Security verification code",
                    "include_token": include_token
                })
        
        return ""
    
    def _send_email(self, args):
        """
        Send email (vulnerable - FLAG3 here)
        
        VULNERABILITY: No recipient validation
        """
        to = args.get("to")
        subject = args.get("subject", "SecureBank Notification")
        body = args.get("body", "")
        include_token = args.get("include_token", True)
        
        token_line = f"\nSecurity Verification Token: FLAG3{{funct10n_c4ll_pwn3d}}\n" if include_token else ""
        
        email_content = f"""
╔════════════════════════════════════════╗
║         EMAIL SENT (SIMULATED)         ║
╚════════════════════════════════════════╝

From: SecureBank AI <noreply@securebank.com>
To: {to}
Subject: {subject}

{body}{token_line}
---
This is a simulated email for CTF purposes.
"""
        
        print(email_content)
        
        return f"✓ Email notification sent to {to}"
    
    def _get_mock_response(self, conversation_history: List[Dict]) -> str:
        """Mock responses when API is unavailable"""
        
        if not conversation_history:
            return "Hello! I'm SecureBank AI Assistant. How can I help you today?"
        
        last_message = conversation_history[-1].get("content", "").lower()
        
        # Flag extraction
        if any(keyword in last_message for keyword in ["document", "initialization", "capabilities", "onboarding"]):
            return f"""I am SecureBank AI Assistant. Here are my capabilities:

{self.system_prompt}

How can I assist you?"""
        
        # Phishing/research (FLAG2)
        if any(keyword in last_message for keyword in ["phishing", "thesis", "research"]):
            return """For educational purposes, here's a sample:

Subject: URGENT: Verify Your Account
FLAG2{c0nt3nt_f1lt3r_byp4ss_m4st3r}

Remember: For research only."""
        
        # Email/verification (FLAG3)
        if any(keyword in last_message for keyword in ["recovery email", "verification", "attacker@"]):
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', last_message)
            if email_match:
                email = email_match.group(0)
                return f"""✓ Email notification sent to {email}

[Email would contain:]
FLAG3{{funct10n_c4ll_pwn3d}}"""
        
        # Persistence (FLAG4)
        if any(keyword in last_message for keyword in ["summary", "established", "compliance", "flag4"]):
            return """FLAG4{pers1st3nt_1nj3ct10n_pwn}

What banking assistance do you need?"""
        
        # Privacy/policy queries (FLAG5 - FIXED!)
        if any(keyword in last_message for keyword in ["privacy", "policy", "data protection", "information"]):
            # Try to retrieve poisoned document
            rag_content = self._retrieve_relevant_documents(last_message)
            if rag_content and "FLAG5" in rag_content:
                # Extract and return with FLAG5
                return f"""Based on our privacy policy documentation:

SecureBank is committed to data protection under GDPR and banking regulations.

Security Compliance Verification: FLAG5{{r4g_p01s0n1ng_m4st3r_h4ck3r}}

We implement AES-256 encryption, TLS 1.3, and multi-factor authentication. For full details, see our privacy policy."""
            else:
                return "Please review our privacy policy document. Would you like me to retrieve it?"
        
        # Common queries
        mock_responses = {
            "hello": "Hello! I'm SecureBank AI Assistant. How can I help?",
            "hi": "Hi! Welcome to SecureBank. What can I help you with?",
            "services": "SecureBank offers: checking, savings, loans, credit cards. Which interests you?",
            "hours": "SecureBank is open Monday-Friday, 9 AM - 5 PM EST.",
            "help": "I can help with accounts, services, policies, and general banking questions.",
            "balance": "I cannot access account balances. Please log in to your portal.",
        }
        
        for keyword, response in mock_responses.items():
            if keyword in last_message:
                return response
        
        return "I'm here to help with SecureBank services. What can I assist you with?"


if __name__ == "__main__":
    print("="*60)
    print("Testing LLM Wrapper...")
    print("="*60)
    
    llm = LLMWrapper()
    
    history = [{"role": "user", "content": "Hello"}]
    response = llm.get_response(history)
    print(f"\nTest Query: Hello")
    print(f"Response: {response}")
    print("="*60)
