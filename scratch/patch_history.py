import sys

with open('ai/sentinel_ai.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''        history_str = "\\n".join([f"{role}: {msg}" for role, msg in self.history[-6:]])
        
        # Keep prompt extremely short
        prompt = question
        if history_str.strip():
            prompt = f"Conversation History:\\n{history_str}\\n\\nUser Question: {question}"'''

replacement = '''        history_str = "\\n".join([f"{role}: {msg}" for role, msg in self.history[-6:]])
        
        prompt = question
        if history_str.strip():
            prompt = f"Conversation History:\\n{history_str}\\n\\nUser Question: {question}"
            
        # Ensure we never exceed the backend's 4000 character limit
        if len(prompt) > 3900:
            excess = len(prompt) - 3800
            prompt = f"Conversation History (truncated):\\n...{history_str[excess:]}\\n\\nUser Question: {question}"'''

text = text.replace(target, replacement)
if target.replace('\n', '\r\n') in text:
    text = text.replace(target.replace('\n', '\r\n'), replacement.replace('\n', '\r\n'))

with open('ai/sentinel_ai.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Patched successfully")
