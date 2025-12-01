# train_model.py
import pandas as pd
import numpy as np
import pickle
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import os
import re
import tldextract

# Define FeatureExtractor at module level (not inside function)
class FeatureExtractor:
    @staticmethod
    def extract_features(url):
        """Extract features from a single URL"""
        features = []
        
        try:
            # 1. URL Length
            features.append(len(url))
            
            # 2. Number of special characters
            special_chars = re.findall(r'[!@#$%^&*()_+\-=\[\]{};\'":|,.<>?]', url)
            features.append(len(special_chars))
            
            # 3. Number of digits
            digits = re.findall(r'\d', url)
            features.append(len(digits))
            
            # 4. Has HTTPS
            features.append(1 if url.lower().startswith('https') else 0)
            
            # 5. URL depth (number of '/')
            features.append(url.count('/'))
            
            # 6. Number of subdomains
            extracted = tldextract.extract(url)
            features.append(extracted.subdomain.count('.') + 1 if extracted.subdomain else 0)
            
            # 7. Contains IP address
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features.append(1 if re.search(ip_pattern, url) else 0)
            
            # 8. URL shortening service check
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 't.co']
            features.append(1 if any(short in url.lower() for short in shorteners) else 0)
            
            # 9. Number of hyphens in domain
            domain = extracted.domain
            features.append(domain.count('-'))
            
            # 10. Domain length
            features.append(len(domain))
            
            # 11. URL entropy (simplified)
            if len(url) > 0:
                entropy = -sum((url.count(c)/len(url)) * np.log2(url.count(c)/len(url)) 
                             for c in set(url) if url.count(c) > 0)
                features.append(entropy)
            else:
                features.append(0)
                
        except:
            # If anything fails, return zeros
            features = [0] * 11
        
        return features

def create_dataset():
    """Create a dataset for training"""
    print("Creating training dataset...")
    
    # Phishing URLs examples
    phishing_urls = [
        "http://secure-paypal-login.com",
        "https://appleid-verify.com/login",
        "http://facebook-secure-login.xyz",
        "http://microsoft-verify-account.com",
        "https://netflix-payment-update.com",
        "http://amazon-security-alert.co.uk",
        "https://google-drive-share-doc.xyz",
        "http://linkedin-profile-verification.com",
        "https://twitter-account-recovery.net",
        "http://192.168.1.100/login",
        "https://10.0.0.1/verify",
        "http://172.16.254.1/secure",
        "http://bit.ly/2x8Z9Yp",
        "https://tinyurl.com/yckjv7pj",
        "http://goo.gl/ABCD123",
        "http://secure-banking.tk",
        "https://account-verify.ml",
        "http://login-update.ga",
        "https://password-reset.cf",
    ]
    
    # Legitimate URLs examples
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
        "https://www.github.com",
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.instagram.com",
        "https://www.reddit.com",
        "https://stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.dropbox.com",
        "https://web.whatsapp.com",
        "https://www.spotify.com",
        "https://www.twitch.tv",
        "http://example.com",
        "https://test.com",
        "http://localhost:8080",
        "https://api.github.com",
    ]
    
    # Generate more samples
    for i in range(100):
        # Add more phishing URLs
        phishing_urls.append(f"http://secure-login-{i}.tk/verify")
        phishing_urls.append(f"https://update-account-{i}.ml/login")
        
        # Add more legitimate URLs
        legitimate_urls.append(f"https://blog.example{i}.com")
        legitimate_urls.append(f"https://api.service{i}.com/data")
    
    # Remove duplicates
    phishing_urls = list(set(phishing_urls))
    legitimate_urls = list(set(legitimate_urls))
    
    print(f"Created {len(phishing_urls)} phishing URLs and {len(legitimate_urls)} legitimate URLs")
    
    # Combine and label
    all_urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    
    return all_urls, labels

def train_and_save_model():
    """Train model and save all required files"""
    print("\n" + "="*60)
    print("PHISHING DETECTION MODEL CREATION")
    print("="*60)
    
    # Create directory if it doesn't exist
    os.makedirs('model', exist_ok=True)
    
    # Create dataset
    urls, labels = create_dataset()
    
    # Extract features
    print("\nExtracting features from URLs...")
    X = []
    for url in urls:
        features = FeatureExtractor.extract_features(url)
        X.append(features)
    
    X = np.array(X)
    y = np.array(labels)
    
    print(f"Feature matrix shape: {X.shape}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    print("\nTraining Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"\nTraining accuracy: {train_score:.2%}")
    print(f"Testing accuracy: {test_score:.2%}")
    
    # Save the model
    model_path = 'model/phishing_model.pkl'
    joblib.dump(model, model_path)
    print(f"\n✓ Model saved to: {model_path}")
    
    # Save feature extractor
    extractor_path = 'model/feature_extractor.pkl'
    with open(extractor_path, 'wb') as f:
        pickle.dump(FeatureExtractor, f)
    print(f"✓ Feature extractor saved to: {extractor_path}")
    
    # Create and save vectorizer
    vectorizer = {
        'type': 'url_feature_extractor',
        'version': '1.0',
        'features': 11,
        'feature_names': [
            'url_length', 'special_chars', 'digits', 'has_https', 'url_depth',
            'subdomains', 'has_ip', 'is_shortened', 'hyphens', 'domain_length', 'entropy'
        ]
    }
    
    vectorizer_path = 'model/vectorizer.pkl'
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    print(f"✓ Vectorizer saved to: {vectorizer_path}")
    
    # Save model metadata
    metadata = {
        'accuracy': float(test_score),
        'training_date': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
        'n_samples': len(urls),
        'model_type': 'RandomForestClassifier'
    }
    
    metadata_path = 'model/metadata.pkl'
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)
    print(f"✓ Model metadata saved to: {metadata_path}")
    
    # Test the model
    print("\n" + "="*60)
    print("TESTING THE MODEL")
    print("="*60)
    
    test_cases = [
        ("https://www.google.com", "Legitimate"),
        ("http://secure-paypal-login.xyz", "Phishing"),
        ("https://github.com", "Legitimate"),
        ("http://bit.ly/malicious", "Phishing"),
        ("https://192.168.1.1/login", "Phishing"),
        ("https://www.microsoft.com", "Legitimate"),
        ("http://fake-bank-login.tk", "Phishing"),
    ]
    
    print("\nSample predictions:")
    correct = 0
    total = len(test_cases)
    
    for url, expected in test_cases:
        features = FeatureExtractor.extract_features(url)
        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0]
        pred_label = "Phishing" if prediction == 1 else "Legitimate"
        confidence = proba[1] if prediction == 1 else proba[0]
        
        if pred_label == expected:
            correct += 1
            status = "✓"
        else:
            status = "✗"
        
        print(f"{status} {url[:40]:<40} -> {pred_label:<12} ({confidence:.1%} confidence)")
    
    print(f"\nTest accuracy: {correct}/{total} ({correct/total:.1%})")
    
    print("\n" + "="*60)
    print("MODEL CREATION COMPLETE!")
    print("="*60)
    print("\nYou can now run the application with:")
    print("  python app.py")
    print("\nThe application will automatically load the model files.")

if __name__ == '__main__':
    try:
        train_and_save_model()
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()