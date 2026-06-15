from phishing_detection.model import PhishingModelManager

manager = PhishingModelManager()
urls = [
    'smilesvoegol.servebbs.org/voegol.php',
    'https://smilesvoegol.servebbs.org/voegol.php',
    'http://smilesvoegol.servebbs.org/voegol.php',
]
for url in urls:
    pred = manager.predict(url)
    print(url, pred.label, pred.confidence, pred.risk)
