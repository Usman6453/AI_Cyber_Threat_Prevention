# ML CV

## Summary
- Built phishing detection model for AI Cyber Threat Prevention app.
- Trained using text and URL features, including the PhiUSIIL dataset.
- Implemented probability calibration and threshold tuning for real-world scoring.

## Skills
- Python, pandas, scikit-learn
- HashingVectorizer, SGDClassifier, CalibratedClassifierCV
- Feature engineering for URLs and phishing text
- Model persistence with joblib and JSON metadata

## Experience
- Developed `PhishingModelManager` to load or retrain models automatically.
- Added training logic for custom dataset input and PhiUSIIL schema support.
- Improved URL extraction for domain-only phishing links.
- Tuned live decision threshold for higher sensitivity while maintaining precision.

## Key impact
- Increased phishing recall on real dataset samples.
- Protected users by catching suspicious URLs and enabling auto-quarantine.
- Created a reusable training workflow for future dataset swaps.
