import sys

with open('ai/provider.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''        url = f"{self.backend_url}/api/v1/ai/chat"
        payload = {
            "message": prompt
        }
        if scan_context:
            payload["context"] = scan_context'''

replacement = '''        url = f"{self.backend_url}/api/v1/ai/chat"
        payload = {
            "message": prompt
        }
        if scan_context:
            payload["context"] = scan_context
        if system_prompt:
            payload["system_instructions"] = system_prompt'''

text = text.replace(target, replacement)
if target.replace('\n', '\r\n') in text:
    text = text.replace(target.replace('\n', '\r\n'), replacement.replace('\n', '\r\n'))

with open('ai/provider.py', 'w', encoding='utf-8') as f:
    f.write(text)
print('Updated provider.py to send system_instructions')
