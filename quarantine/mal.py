# detection_example.py
import psutil
import joblib
import numpy as np

class MalwareDetector:
    def __init__(self, model_path='malware_detection_model.pkl'):
        self.model = joblib.load(model_path)
        
    def extract_features_from_process(self, process_name):
        """
        Extract features from a running process (ALL DATA IS BENIGN)
        This is for EDUCATIONAL purposes only
        """
        try:
            process = None
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                if proc.info['name'] == process_name:
                    process = proc
                    break
            
            if not process:
                return None
            
            # Extract harmless features
            features = {
                'create_process_calls': len(process.children()),
                'network_connections': len(process.connections()),
                'memory_allocation_calls': process.memory_info().rss / 1024 / 1024,  # MB
                'suspicious_file_ops': 0,  # Would require monitoring
                'code_injection_attempts': 0,
                'process_hollowing': 0,
                'privilege_escalation': 1 if 'root' in process.username() else 0,
            }
            
            return features
            
        except Exception as e:
            print(f"Error analyzing process: {e}")
            return None
    
    def predict(self, features):
        """Predict if process is malicious"""
        if features:
            features_array = np.array([list(features.values())])
            prediction = self.model.predict(features_array)
            probability = self.model.predict_proba(features_array)
            
            return {
                'is_malicious': bool(prediction[0]),
                'confidence': float(max(probability[0])),
                'risk_score': float(probability[0][1])
            }
        return None

# Example usage
if __name__ == "__main__":
    detector = MalwareDetector()
    
    # Check a specific process (example)
    test_process = "python.exe"  # Benign example
    features = detector.extract_features_from_process(test_process)
    
    if features:
        result = detector.predict(features)
        print(f"Process: {test_process}")
        print(f"Malicious: {result['is_malicious']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Risk Score: {result['risk_score']:.2%}")