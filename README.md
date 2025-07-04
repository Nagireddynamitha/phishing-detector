# 🔍 AI-Free Phishing URL Detection Tool

A lightweight, rule-based phishing link detector built with Python — no machine learning, no AI — just pure logic.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🚀 Features

- ✅ Detects **non-HTTPS** URLs
- ✅ Flags **suspicious TLDs** like `.tk`, `.ml`, `.cf`
- ✅ Highlights **common phishing keywords** like `login`, `secure`, `verify`
- ✅ Checks for **long or unusual domains**
- ✅ Simple, AI-free, transparent logic

---

## 🧪 Example Input

**phishing_urls.txt**
```txt
http://login-facebook.tk
https://secure-update-amazon.ml
https://accounts.google.com
http://gmail-login123.cf
https://github.com
