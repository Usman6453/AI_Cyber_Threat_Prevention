#!/usr/bin/env python
"""Test script to validate phishing detection fixes"""
import sys
sys.path.insert(0, str(__file__).replace('scripts\\test_detection_fix.py', ''))

from phishing_detection.model import PhishingModelManager

model = PhishingModelManager()

# Test safe URLs
test_urls = [
    'https://www.youtube.com',
    'https://www.google.com',
    'https://github.com',
    'https://stackoverflow.com',
    'https://www.wikipedia.org',
    'https://www.amazon.com',
    'https://www.facebook.com',
    # Malicious URLs (should be detected)
    'smilesvoegol.servebbs.org/voegol.php',
    'https://login-verify-account.com',
    'https://secure-bank-confirm.com',
    'https://192.168.1.1/verify',
    'https://amazon-confirm-update.xyz',
    'https://urgent-update-password-reset.com',
]

print('Phishing Detection Test Results:')
print('=' * 90)
for url in test_urls:
    pred = model.predict(url)
    status = '✓ SAFE' if pred.label == 'safe' else '✗ PHISHING'
    print(f'{status} | {url:55} | Conf: {pred.confidence:.1%} | {pred.risk.upper()}')

print('=' * 90)
print('\nExpected Results:')
print('- YouTube, Google, GitHub, etc. should show ✓ SAFE')
print('- login-verify-account, secure-bank-confirm, IP-based should show ✗ PHISHING')
