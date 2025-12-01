# setup_model.py
import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    print("Installing requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "scikit-learn", "pandas", "numpy", "joblib", "tldextract"])

def create_model():
    """Create the model files"""
    print("\nCreating model files...")
    
    # Import and run training
    from train_simple_model import train_and_save_model
    train_and_save_model()

def main():
    print("="*60)
    print("PHISHING DETECTION SYSTEM - MODEL SETUP")
    print("="*60)
    
    # Create model directory
    os.makedirs('model', exist_ok=True)
    
    try:
        install_requirements()
        create_model()
        
        print("\n" + "="*60)
        print("SETUP COMPLETE!")
        print("="*60)
        print("\nGenerated files:")
        print("  model/phishing_model.pkl - Main ML model")
        print("  model/feature_extractor.pkl - Feature extraction logic")
        print("  model/vectorizer.pkl - Vectorizer file")
        print("  model/model_info.pkl - Model metadata")
        print("\nTo start the application: python app.py")
        
    except Exception as e:
        print(f"\nError during setup: {e}")

if __name__ == '__main__':
    main()