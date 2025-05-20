# 🔒 CipherVault
A no-nonsense encryption tool that works right in your browser. Encrypt messages with classic ciphers or RSA, then decrypt them no server needed. Built with vanilla JS for privacy nerds and curious learners.

## Features

- **Encrypt** text with:
  - Caesar cipher (shift letters)
  - Vigenère cipher (keyword-based)
  - RSA (secure public/private keys)
  - Base64 encoding
  - SHA-256 hashing

- **Decrypt** messages (except hashes)
- Save encrypted messages per user
- Copy results with one click
- Works offline after loading

## How to Use

1. **Login** (demo credentials: admin/password123)
2. **Encrypt**:
   - Type your message
   - Choose method
   - Click Encrypt
3. **Decrypt**:
   - Paste encrypted text
   - Select same method
   - Click Decrypt

For RSA:
- First encryption generates keys automatically
- Export/Import keys to use across devices

## Tech Used

- Plain JavaScript (no frameworks)
- Web Crypto API for RSA/SHA-256
- localStorage for user data
- CSS Flexbox/Grid for layout

## Setup

Just open `index.html` in any modern browser. No server needed.

## Notes

- All processing happens in your browser
- Keys never leave your device
- Refresh clears RSA keys unless exported
- [![Browser-Based](https://img.shields.io/badge/Runs%20In-Browser-blue)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) 
[![No Server](https://img.shields.io/badge/No%20Server%20Needed-success)](https://en.wikipedia.org/wiki/Client-side_encryption)

