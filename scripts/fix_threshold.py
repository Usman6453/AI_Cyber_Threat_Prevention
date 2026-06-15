#!/usr/bin/env python
"""Fix phishing threshold to 0.3 (30%) for aggressive detection"""
import re

model_file = "phishing_detection/model.py"

with open(model_file, 'r') as f:
    content = f.read()

# Replace threshold from 0.5 to 0.3
content = re.sub(
    r"threshold = 0\.5",
    "threshold = 0.3",
    content
)

# Add comment explaining 0.3 threshold
content = re.sub(
    r"# Use very aggressive threshold.*?\n        threshold = 0\.3",
    "# Use AGGRESSIVE threshold (0.3 = 30%) - catches malicious URLs immediately\n        # Whitelisted safe domains bypass this and return safe\n        threshold = 0.3",
    content
)

with open(model_file, 'w') as f:
    f.write(content)

print("✓ Updated phishing_detection/model.py")
print("✓ Threshold set to 0.3 (30%)")
print("✓ Any URL with ≥30% malicious confidence = PHISHING")
print("\n✓ Existing trained model preserved.")
print("✓ No retraining will be forced by this script.")
