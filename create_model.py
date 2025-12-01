# create_model.py
import pickle
import joblib
import numpy as np

print("Creating minimal model files...")

# Create a simple model
class SimpleModel:
    def predict(self, X):
        # Simple rule-based prediction
        # URL length > 50 -> phishing, else legitimate
        return [1 if x[0] > 50 else 0 for x in X]
    
    def predict_proba(self, X):
        # Return probabilities
        predictions = self.predict(X)
        return [[1-p, p] if p == 1 else [1, 0] for p in predictions]

# Create model
model = SimpleModel()

# Save model
joblib.dump(model, 'model/phishing_model.pkl')
print("✓ Model saved: model/phishing_model.pkl")

# Save feature extractor
class FeatureExtractor:
    @staticmethod
    def extract_features(url):
        return [len(url), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

with open('model/feature_extractor.pkl', 'wb') as f:
    pickle.dump(FeatureExtractor, f)
print("✓ Feature extractor saved: model/feature_extractor.pkl")

# Save vectorizer
vectorizer = {'type': 'simple', 'features': 11}
with open('model/vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)
print("✓ Vectorizer saved: model/vectorizer.pkl")

print("\nAll files created! You can now run: python app.py")