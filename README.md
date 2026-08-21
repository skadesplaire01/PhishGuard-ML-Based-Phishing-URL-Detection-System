# 🛡️ PhishGuard — ML-Based Phishing URL Detection System

Phishing attacks often use deceptive URLs to trick users into visiting malicious
websites or entering sensitive information. PhishGuard analyzes a submitted URL
using Machine Learning and URL-level security checks to identify potentially
phishing links and explain the suspicious characteristics behind the result.

🔗 **Live Demo:** https://phishguard-ml-based-phishing-url.onrender.com

---

## 🎯 Problem

Phishing URLs can look similar to legitimate websites, making it difficult for
users to identify malicious links before opening them.

## 💡 Solution

PhishGuard combines a trained Machine Learning classifier with rule-based URL
analysis to:

- Detect potentially phishing URLs
- Identify suspicious URL characteristics
- Provide model confidence
- Highlight security signals
- Display an understandable risk assessment

---

## ✨ Key Features

- 🤖 **ML-Based URL Classification**
  - Classifies URLs as `Good` or `Bad`
  - Uses a trained Logistic Regression model

- 🔎 **URL Security Analysis**
  - URL length analysis
  - HTTPS detection
  - IP address detection
  - Suspicious keyword detection
  - Subdomain analysis
  - Special-character checks

- 📊 **Risk Assessment**
  - Combines detection signals into an easy-to-understand risk level

- 💡 **Explainable Results**
  - Shows why a URL may be considered suspicious instead of providing
    only a binary prediction

- 📋 **Scan History**
  - Displays recently analyzed URLs and their results

- 🌐 **Web Application**
  - Interactive Flask-based interface

- ☁️ **Cloud Deployment**
  - Deployed using Render with Gunicorn

---

## ⚙️ How It Works

```text
User enters URL
       ↓
URL Preprocessing
       ↓
CountVectorizer
       ↓
Logistic Regression Model
       ↓
Good / Phishing Prediction
       ↓
URL Security Checks
       ↓
Risk Level + Security Signals
       ↓
Explainable Result
```

## 🧠 ML Pipeline

### Dataset

The project uses a dataset containing **549,346 URLs**:

- `392,924` Good URLs
- `156,422` Bad URLs

### Processing

```text
Raw URLs
   ↓
Tokenization
   ↓
Stemming
   ↓
Text Representation
   ↓
CountVectorizer
   ↓
Train/Test Split
   ↓
Logistic Regression
   ↓
Prediction
```
---

## 🛠️ Tech Stack

### Programming
- Python

### Machine Learning
- Scikit-learn
- Logistic Regression
- Multinomial Naive Bayes
- CountVectorizer

### Data Processing
- Pandas
- NumPy
- NLTK

### Web Development
- Flask
- HTML
- CSS
- JavaScript

### Deployment & Tools
- Gunicorn
- Render
- Git
- GitHub
- VS Code

---
## 📁 Project Structure

```text
Phishing-Website-Detection-System/
│
├── Dataset/
│   └── phishing_site_urls.csv
│
├── templates/
│   └── index.html
│
├── app.py
├── phishing.pkl
├── phishing_mnb.pkl
├── vectorizer.pkl
├── requirements.txt
│
├── Phishing website detection system.ipynb
└── word2vec.ipynb
```
---

## 📸 Screenshots

### 🔍 URL Detection

![PhishGuard URL Detection](https://github.com/skadesplaire01/PhishGuard-ML-Based-Phishing-URL-Detection-System/blob/main/URL%20DET.jpg?raw=true)

### 🚨 Phishing Detection Result

![PhishGuard Phishing Detection](https://github.com/skadesplaire01/PhishGuard-ML-Based-Phishing-URL-Detection-System/blob/main/Phishing%20Det%20result.jpg?raw=true)

### 🛡️ Security Analysis

![PhishGuard Security Analysis](https://github.com/skadesplaire01/PhishGuard-ML-Based-Phishing-URL-Detection-System/blob/main/security%20analysis%20and%20history.jpg?raw=true)







