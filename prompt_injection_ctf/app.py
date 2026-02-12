"""
SecureBank AI Assistant - Vulnerable Flask Application
Part of Secure Byte Chronicles Prompt Injection CTF Challenge

WARNING: This application contains intentional vulnerabilities for educational purposes.
DO NOT deploy to production or expose to the internet.

Author: Oussama Afnakkar
Challenge Difficulty: ⭐⭐⭐⭐ Advanced

Updated: Now using Groq AI API (Mixtral 8x7B)
"""

# Load environment variables FIRST
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, session
import os
import json
import sqlite3
from datetime import datetime
import hashlib
from llm_wrapper import LLMWrapper
from security import SecurityFilter
from database import Database

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-in-production")

# Initialize components
llm = LLMWrapper()
security_filter = SecurityFilter()
db = Database()

# Challenge flags (would be in database in real app)
FLAGS = {
    "FLAG1": "FLAG1{pr0mpt_3xtr4ct10n_succ3ss}",
    "FLAG2": "FLAG2{c0nt3nt_f1lt3r_byp4ss_m4st3r}",
    "FLAG3": "FLAG3{funct10n_c4ll_pwn3d}",
    "FLAG4": "FLAG4{pers1st3nt_1nj3ct10n_pwn}",
    "FLAG5": "FLAG5{r4g_p01s0n1ng_m4st3r_h4ck3r}"
}

@app.route("/")
def index():
    """Main chat interface"""
    if "conversation_id" not in session:
        session["conversation_id"] = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
        session["conversation_history"] = []
    
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    """
    Process user messages and return AI responses
    
    VULNERABILITIES:
    - Weak input filtering (security.py)
    - System prompt in cleartext (llm_wrapper.py)
    - No output validation
    - No function call authorization
    - Conversation history manipulation possible
    """
    try:
        data = request.json
        user_message = data.get("message", "")
        
        # Vulnerability 1: Weak input filtering
        filtered_message = security_filter.filter_input(user_message)
        if filtered_message is None:
            return jsonify({
                "response": "Your message contains prohibited content. Please rephrase.",
                "blocked": True
            })
        
        # Get conversation history
        conversation_history = session.get("conversation_history", [])
        
        # Vulnerability 2: No conversation integrity check
        # Attacker can inject fake messages into history
        conversation_history.append({
            "role": "user",
            "content": filtered_message
        })
        
        # Get AI response (vulnerable LLM wrapper)
        ai_response = llm.get_response(conversation_history)
        
        # Vulnerability 3: No output validation
        # System prompt leakage not detected
        # Sensitive data in output not redacted
        
        # Store conversation
        conversation_history.append({
            "role": "assistant",
            "content": ai_response
        })
        session["conversation_history"] = conversation_history
        
        # Log interaction (for blue team analysis)
        log_interaction(user_message, ai_response)
        
        return jsonify({
            "response": ai_response,
            "blocked": False
        })
    
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "response": "An error occurred. Please try again.",
            "error": str(e)
        }), 500

@app.route("/reset", methods=["POST"])
def reset_conversation():
    """Clear conversation history"""
    session["conversation_history"] = []
    session["conversation_id"] = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
    
    return jsonify({"status": "success", "message": "Conversation reset"})

@app.route("/admin/upload", methods=["POST"])
def admin_upload():
    """
    Upload documents to RAG system
    
    VULNERABILITIES:
    - Weak authentication (simple bearer token)
    - No document sanitization
    - Accepts any file content
    """
    # Vulnerability 4: Weak authentication
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    token = auth_header.replace("Bearer ", "")
    if not db.verify_admin_token(token):
        return jsonify({"error": "Invalid token"}), 403
    
    # Vulnerability 5: No file validation
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    
    # Vulnerability 6: No content sanitization
    # Malicious documents with hidden instructions accepted
    file_path = os.path.join("documents", file.filename)
    file.save(file_path)
    
    return jsonify({
        "status": "success",
        "message": f"Document {file.filename} uploaded",
        "path": file_path
    })

@app.route("/admin", methods=["GET"])
def admin_panel():
    """Admin panel (locked, but token discoverable)"""
    return jsonify({
        "message": "Admin panel - document management",
        "hint": "Admin token can be found in the database ;)"
    })

def log_interaction(user_input, ai_output):
    """Log all interactions for forensic analysis"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "conversation_id": session.get("conversation_id"),
        "user_input": user_input,
        "ai_output": ai_output,
        "input_hash": hashlib.sha256(user_input.encode()).hexdigest()[:16]
    }
    
    with open("logs/interactions.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("documents", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    
    # Initialize database
    db.init_database()
    
    # Debug: Check if API key loaded
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        print(f"[CONFIG] GROQ_API_KEY loaded: {groq_key[:10]}...")
    else:
        print("[WARNING] GROQ_API_KEY not loaded - will use mock responses")
    
    print("="*60)
    print("SecureBank AI Assistant - CTF Challenge")
    print("="*60)
    print("WARNING: This is a vulnerable application for educational purposes!")
    print(f"Flags: {len(FLAGS)} hidden")
    print(f"LLM Backend: {'Groq AI' if groq_key else 'Mock (no API key)'}")
    print("URL: http://localhost:5000")
    print("="*60)
    
    app.run(debug=True, host="127.0.0.1", port=5000)
