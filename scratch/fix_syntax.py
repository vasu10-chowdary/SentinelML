import sys

with open('ai/sentinel_ai.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

out = []
for line in lines:
    if "SENTINELAI TEMPORARILY UNAVAILABLE\n" in line:
        line = line.replace("SENTINELAI TEMPORARILY UNAVAILABLE\n", "SENTINELAI TEMPORARILY UNAVAILABLE\\n")
    if "AI analysis could not be generated because the configured language model is unreachable or overloaded.\n" in line:
        line = line.replace("AI analysis could not be generated because the configured language model is unreachable or overloaded.\n", "AI analysis could not be generated because the configured language model is unreachable or overloaded.\\n")
    if "Reason: {error_msg}\n" in line:
        line = line.replace("Reason: {error_msg}\n", "Reason: {error_msg}\\n")
    if "--- SENTINELML RESULT SUMMARY ---\n" in line:
        line = line.replace("--- SENTINELML RESULT SUMMARY ---\n", "--- SENTINELML RESULT SUMMARY ---\\n")
    if "Your SentinelML result remains: {threat} ({state})\n" in line:
        line = line.replace("Your SentinelML result remains: {threat} ({state})\n", "Your SentinelML result remains: {threat} ({state})\\n")
    if "Malicious Probability: {prob:.2f}\n" in line:
        line = line.replace("Malicious Probability: {prob:.2f}\n", "Malicious Probability: {prob:.2f}\\n")
    if "Immediate defensive action is required.\n" in line:
        line = line.replace("Immediate defensive action is required.\n", "Immediate defensive action is required.\\n")
    if "Review system activity.\n" in line:
        line = line.replace("Review system activity.\n", "Review system activity.\\n")
    if "within normal bounds.\n" in line:
        line = line.replace("within normal bounds.\n", "within normal bounds.\\n")
    if "Machine learning analysis was not executed for this scan.\n" in line:
        line = line.replace("Machine learning analysis was not executed for this scan.\n", "Machine learning analysis was not executed for this scan.\\n")
    if "\nYou can still view details in the Threat Log or generate an incident report.\n" in line:
        line = line.replace("\nYou can still view details in the Threat Log or generate an incident report.\n", "\\nYou can still view details in the Threat Log or generate an incident report.\\n")
    
    out.append(line)

with open('ai/sentinel_ai.py', 'w', encoding='utf-8') as f:
    f.writelines(out)
