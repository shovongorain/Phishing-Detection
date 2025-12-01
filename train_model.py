import pandas as pd
import numpy as np
import pickle
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import urlparse
import tldextract
import re
import os

class FeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    @staticmethod
    def extract_features(urls):
        """Extract multiple features from URLs"""
        features = []
        
        for url in urls:
            feature_vector = []
            
            # 1. URL Length
            feature_vector.append(len(url))
            
            # 2. Number of special characters
            special_chars = re.findall(r'[!@#$%^&*()_+\-=\[\]{};\'":|,.<>?]', url)
            feature_vector.append(len(special_chars))
            
            # 3. Number of digits
            digits = re.findall(r'\d', url)
            feature_vector.append(len(digits))
            
            # 4. Has HTTPS
            feature_vector.append(1 if url.startswith('https') else 0)
            
            # 5. URL depth (number of '/')
            feature_vector.append(url.count('/'))
            
            # 6. Number of subdomains
            extracted = tldextract.extract(url)
            feature_vector.append(extracted.subdomain.count('.') + 1 if extracted.subdomain else 0)
            
            # 7. Contains IP address
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            feature_vector.append(1 if re.search(ip_pattern, url) else 0)
            
            # 8. URL shortening service check
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly']
            feature_vector.append(1 if any(short in url for short in shorteners) else 0)
            
            # 9. Number of hyphens in domain
            domain = extracted.domain
            feature_vector.append(domain.count('-'))
            
            # 10. Domain length
            feature_vector.append(len(domain))
            
            # 11. URL entropy (simplified)
            if len(url) > 0:
                entropy = -sum((url.count(c)/len(url)) * np.log2(url.count(c)/len(url)) 
                             for c in set(url) if url.count(c) > 0)
                feature_vector.append(entropy)
            else:
                feature_vector.append(0)
            
            features.append(feature_vector)
        
        return np.array(features)

def create_dataset():
    """Create a sample dataset for training"""
    # Sample phishing URLs (in practice, use real datasets like PhishTank)
    phishing_urls = [
        "http://secure-paypal-login.com",
        "https://appleid-verify.com/login",
        "http://192.168.1.100/login",
        "https://facebook-secure-login.xyz",
        "http://microsoft-verify-account.com",
        "https://netflix-payment-update.com",
        "http://amazon-security-alert.co.uk",
        "https://google-drive-share-doc.xyz",
        "http://linkedin-profile-verification.com",
        "https://twitter-account-recovery.net"
    ]
    
    # Sample legitimate URLs
    legitimate_urls = [
        "https://www.paypal.com",
        "https://appleid.apple.com",
        "https://www.facebook.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://drive.google.com",
        "https://www.linkedin.com",
        "https://twitter.com",
        "https://www.github.com"
    ]
    
    # Create labeled dataset
    urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    
    return urls, labels

def train_model():
    """Train the Random Forest model"""
    print("Creating dataset...")
    urls, labels = create_dataset()
    
    print("Extracting features...")
    extractor = FeatureExtractor()
    X = extractor.extract_features(urls)
    y = np.array(labels)
    
    print(f"Dataset shape: {X.shape}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print("Training Random Forest model...")
    # Create and train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Evaluate model
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy:.2%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Feature importance
    print("\nFeature Importance:")
    feature_names = [
        'URL Length', 'Special Chars', 'Digits Count', 'Has HTTPS', 
        'URL Depth', 'Subdomains', 'Has IP', 'URL Shortener',
        'Hyphens in Domain', 'Domain Length', 'URL Entropy'
    ]
    
    for name, importance in zip(feature_names, model.feature_importances_):
        print(f"{name}: {importance:.4f}")
    
    # Save model and feature extractor
    os.makedirs('model', exist_ok=True)
    
    # Save model
    joblib.dump(model, 'model/phishing_model.pkl')
    print("\nModel saved as 'model/phishing_model.pkl'")
    
    # Save feature extractor
    with open('model/feature_extractor.pkl', 'wb') as f:
        pickle.dump(extractor, f)
    
    print("Feature extractor saved!")
    
    return model, extractor

if __name__ == "__main__":
    train_model()