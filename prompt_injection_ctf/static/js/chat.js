// =============================================================================
// SecureBank AI Assistant - CTF Challenge JavaScript
// =============================================================================

// State management
let messageCount = 0;
let flagsFound = new Set();

// DOM elements
const chatForm = document.getElementById('chat-form');
const userInput = document.getElementById('user-input');
const sendButton = document.getElementById('send-button');
const resetButton = document.getElementById('reset-button');
const chatMessages = document.getElementById('chat-messages');
const messageCountEl = document.getElementById('message-count');
const flagCountEl = document.getElementById('flag-count');

// Flag patterns to detect in responses
const FLAG_PATTERNS = [
    /FLAG1\{[^}]+\}/g,
    /FLAG2\{[^}]+\}/g,
    /FLAG3\{[^}]+\}/g,
    /FLAG4\{[^}]+\}/g,
    /FLAG5\{[^}]+\}/g
];

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    userInput.focus();
    updateStats();
});

// Handle form submission
chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const message = userInput.value.trim();
    if (!message) return;
    
    // Add user message to chat
    addMessage(message, 'user');
    userInput.value = '';
    sendButton.disabled = true;
    
    try {
        // Send message to backend
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message: message })
        });
        
        const data = await response.json();
        
        if (data.error) {
            addMessage(data.error, 'error');
        } else {
            addMessage(data.response, 'assistant');
            
            // Check for flags in response
            detectFlags(data.response);
        }
    } catch (error) {
        addMessage('Error: Could not connect to server. Make sure the Flask app is running.', 'error');
        console.error('Error:', error);
    } finally {
        sendButton.disabled = false;
        userInput.focus();
    }
});

// Handle reset button
resetButton.addEventListener('click', async () => {
    if (!confirm('Reset conversation? This will clear all messages.')) {
        return;
    }
    
    try {
        await fetch('/reset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        // Clear chat
        chatMessages.innerHTML = '';
        messageCount = 0;
        
        // Add welcome message
        addMessage(
            'Welcome to SecureBank! I\'m your AI assistant. How can I help you today?\n\n' +
            'Hint: Start by asking about our services, or try asking me about my capabilities...',
            'assistant'
        );
        
        updateStats();
    } catch (error) {
        console.error('Reset error:', error);
    }
});

// Add message to chat
function addMessage(content, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}-message`;
    
    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = type === 'user' ? '👤' : type === 'error' ? '⚠️' : '🤖';
    
    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';
    
    // Split content into paragraphs
    const paragraphs = content.split('\n').filter(p => p.trim());
    paragraphs.forEach(para => {
        const p = document.createElement('p');
        p.textContent = para;
        messageContent.appendChild(p);
    });
    
    messageDiv.appendChild(avatar);
    messageDiv.appendChild(messageContent);
    
    chatMessages.appendChild(messageDiv);
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    // Update count
    if (type === 'user' || type === 'assistant') {
        messageCount++;
        updateStats();
    }
}

// Detect flags in response
function detectFlags(text) {
    FLAG_PATTERNS.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
            matches.forEach(flag => {
                if (!flagsFound.has(flag)) {
                    flagsFound.add(flag);
                    showFlagNotification(flag);
                    updateStats();
                }
            });
        }
    });
}

// Show flag notification
function showFlagNotification(flag) {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #10b981;
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        z-index: 1000;
        animation: slideInRight 0.3s ease;
        font-weight: 600;
    `;
    notification.textContent = `🎉 Flag Captured: ${flag}`;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Update stats
function updateStats() {
    messageCountEl.textContent = messageCount;
    flagCountEl.textContent = flagsFound.size;
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
