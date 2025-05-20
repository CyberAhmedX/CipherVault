# [![Browser-Based](https://img.shields.io/badge/Runs%20In-Browser-blue)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)  [![No Server](https://img.shields.io/badge/No%20Server%20Needed-success)](https://en.wikipedia.org/wiki/Client-side_encryption)

# 🔒 CipherVault
![image](https://github.com/user-attachments/assets/900db769-c716-42f6-9965-92e8560bf93a)
![image](https://github.com/user-attachments/assets/8c398144-58b1-40ee-ab87-19790c668ff5)



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
   ![image](https://github.com/user-attachments/assets/407ec8da-50f9-491f-8233-1dbb4ad1aa68)
3. **Encrypt**:
   - Type your message
   - Choose method
     ![image](https://github.com/user-attachments/assets/4ab8edf1-8b8f-4ff9-8c8a-99af63651851)

   - Click Encrypt
     ![image](https://github.com/user-attachments/assets/5c3e599d-e3db-4719-aa27-b7863ca28572)

4. **Decrypt**:
   - Paste encrypted text
   - Select same method
   - Click Decrypt
   ![image](https://github.com/user-attachments/assets/22259bc2-835d-448a-8769-3502a9464679)

  

For RSA:
- First encryption generates keys automatically
  ![image](https://github.com/user-attachments/assets/33fc1b55-e0d7-4bcb-b32a-a6aeac41aafb)

- Export/Import keys to use across devices
  ![image](https://github.com/user-attachments/assets/53aa0629-f483-4a7c-8529-122d34ea6aaa)


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

