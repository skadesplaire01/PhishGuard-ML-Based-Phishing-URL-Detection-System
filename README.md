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
