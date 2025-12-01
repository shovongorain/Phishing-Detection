@echo off
echo ========================================
echo Phishing Detection System Setup
echo ========================================
echo.

echo Step 1: Creating model directory...
if not exist "model" mkdir model

echo Step 2: Installing required packages...
pip install Flask==2.3.3 scikit-learn==1.3.0 pandas==2.0.3 numpy==1.24.3 joblib==1.3.2 tldextract==3.4.4 flask-cors==4.0.0

echo Step 3: Training the model...
python train_model.py

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To start the application, run:
echo python app.py
echo.
pause