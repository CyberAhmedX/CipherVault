
async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;


  if (username === "admin" && password === "password123") {
   
    const token = "demo_token_" + Math.random().toString(36).substring(2);
    localStorage.setItem("authToken", token);
    localStorage.setItem("currentUser", username);

    document.getElementById("loginBox").style.display = "none";
    document.getElementById("appContent").style.display = "block";
  } else {
    alert("Invalid credentials. Try admin / password123.");
  }
}


function toggleKeyField() {
  const algo = document.getElementById("algorithm").value;

 
  document.getElementById("keyCaesar").style.display = "none";
  document.getElementById("keyVigenere").style.display = "none";
  document.getElementById("keyRSA").style.display = "none";

  
  if (algo === "caesar") {
    document.getElementById("keyCaesar").style.display = "block";
  } else if (algo === "vigenere") {
    document.getElementById("keyVigenere").style.display = "block";
  } else if (algo === "rsa") {
    document.getElementById("keyRSA").style.display = "block";
  }
}
function toggleDecryptKeyField() {
  const algo = document.getElementById("decryptAlgo").value;

  document.getElementById("decryptKeyCaesar").style.display = "none";
  document.getElementById("decryptKeyVigenere").style.display = "none";
  document.getElementById("decryptKeyRSA").style.display = "none";

  if (algo === "caesar") {
    document.getElementById("decryptKeyCaesar").style.display = "block";
  } else if (algo === "vigenere") {
    document.getElementById("decryptKeyVigenere").style.display = "block";
  } else if (algo === "rsa") {
    document.getElementById("decryptKeyRSA").style.display = "block";
  }
}



function caesarCipherEncrypt(text, key) {
  const shift = parseInt(key) || 0;
  return text.split('').map(char => {
    let code = char.charCodeAt(0);
    if (char.match(/[a-z]/i)) {
      let base = code >= 65 && code <= 90 ? 65 : 97;
      return String.fromCharCode((code - base + shift) % 26 + base);
    }
    return char;
  }).join('');
}

function caesarCipherDecrypt(text, key) {
  const shift = parseInt(key) || 0;
  return caesarCipherEncrypt(text, 26 - shift);
}


function vigenereEncrypt(text, key) {
  let result = "", j = 0;
  key = key.toLowerCase();
  for (let i = 0; i < text.length; i++) {
    let char = text[i];
    if (char.match(/[a-z]/i)) {
      let base = char === char.toUpperCase() ? 65 : 97;
      let shift = key.charCodeAt(j % key.length) - 97;
      result += String.fromCharCode((char.charCodeAt(0) - base + shift) % 26 + base);
      j++;
    } else result += char;
  }
  return result;
}

function vigenereDecrypt(text, key) {
  let result = "", j = 0;
  key = key.toLowerCase();
  for (let i = 0; i < text.length; i++) {
    let char = text[i];
    if (char.match(/[a-z]/i)) {
      let base = char === char.toUpperCase() ? 65 : 97;
      let shift = key.charCodeAt(j % key.length) - 97;
      result += String.fromCharCode((char.charCodeAt(0) - base - shift + 26) % 26 + base);
      j++;
    } else result += char;
  }
  return result;
}

let rsaKeyPair = null; 


async function generateRSAKeyPair() {
  try {
    rsaKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, 
      ["encrypt", "decrypt"]
    );
    console.log("New RSA keys generated");
    return rsaKeyPair;
  } catch (error) {
    console.error("Key generation failed:", error);
    throw error;
  }
}


async function rsaEncrypt(text) {
  try {
   
    if (!rsaKeyPair) {
      console.log("No RSA keys found - generating new pair");
      await generateRSAKeyPair();
    }

    const encrypted = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaKeyPair.publicKey,
      new TextEncoder().encode(text)
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  } catch (error) {
    console.error("RSA encryption failed:", error);
    return `Encryption error: ${error.message}`;
  }
}


async function rsaDecrypt(text) {
  try {
    if (!rsaKeyPair) {
      throw new Error("No RSA keys available - encrypt first or import keys");
    }

    const encryptedData = Uint8Array.from(atob(text), c => c.charCodeAt(0));
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      rsaKeyPair.privateKey,
      encryptedData
    );
    
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("RSA decryption failed:", error);
    return `Decryption error: ${error.message}`;
  }
}



async function exportRSAKeys() {
  if (!rsaKeyPair) await generatersaKeyPair();
  
  const exportedPublic = await crypto.subtle.exportKey("jwk", rsaKeyPair.publicKey);
  const exportedPrivate = await crypto.subtle.exportKey("jwk", rsaKeyPair.privateKey);
  
 
  document.getElementById("publicKeyDisplay").value = JSON.stringify(exportedPublic, null, 2);
  document.getElementById("privateKeyDisplay").value = JSON.stringify(exportedPrivate, null, 2);
  document.getElementById("keyExportModal").style.display = "flex";
  

  localStorage.setItem('rsaKeys', JSON.stringify({
    publicKey: exportedPublic,
    privateKey: exportedPrivate
  }));
}


function copyKey(elementId) {
  const textarea = document.getElementById(elementId);
  textarea.select();
  document.execCommand('copy');
  alert('Key copied to clipboard!');
}

async function importRSAKeys() {
  const publicKeyJwk = prompt("Paste your RSA Public Key (JWK format):");
  const privateKeyJwk = prompt("Paste your RSA Private Key (JWK format):");
  
  if (!publicKeyJwk || !privateKeyJwk) return;
  
  try {
    rsaKeyPair = {
      publicKey: await crypto.subtle.importKey(
        "jwk",
        JSON.parse(publicKeyJwk),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      ),
      privateKey: await crypto.subtle.importKey(
        "jwk",
        JSON.parse(privateKeyJwk),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
      )
    };
    alert("RSA keys imported successfully!");
  } catch (error) {
    alert(`Failed to import keys: ${error.message}`);
  }
}


async function sha256Hash(text) {
  const buffer = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


async function encryptText() {
  const plainText = document.getElementById("plaintext").value;
  const algo = document.getElementById("algorithm").value;
  let key = "";
  if (algo === "caesar") key = document.getElementById("caesarKey").value;
  if (algo === "vigenere") key = document.getElementById("vigenereKey").value;


  if (!plainText || !algo) {
    alert("Please enter text and select a method.");
    return;
  }

  let result = "";



  switch (algo) {
    case "caesar":
      if (!key) return alert("Caesar Cipher needs a key (number).");
      result = caesarCipherEncrypt(plainText, key);
      break;
    case "vigenere":
      if (!key) return alert("Vigenère Cipher needs a key.");
      result = vigenereEncrypt(plainText, key);
      break;
    case "base64":
      result = btoa(plainText);
      break;
    case "rsa":
      result = await rsaEncrypt(plainText);
      break;
    case "sha256":
      result = await sha256Hash(plainText);
      break;
    default:
      result = "Invalid encryption method.";
  }

  let currentUser = localStorage.getItem("currentUser");
  if (currentUser) {
  let stored = JSON.parse(localStorage.getItem(currentUser + "_messages")) || [];
  stored.push({ original: plainText, encrypted: result, method: algo });
  localStorage.setItem(currentUser + "_messages", JSON.stringify(stored));
  }

  document.getElementById("ciphertext").value = result;
}


async function decryptText() {
  const cipherText = document.getElementById("plaintext").value;
  const algo = document.getElementById("algorithm").value;
  let key = "";
  if (algo === "caesar") key = document.getElementById("caesarKey").value;
  if (algo === "vigenere") key = document.getElementById("vigenereKey").value;


  if (!cipherText || !algo) {
    alert("Please enter ciphertext and select a method.");
    return;
  }

  let result = "";

  switch (algo) {
    case "caesar":
      result = caesarCipherDecrypt(cipherText, key);
      break;
    case "vigenere":
      result = vigenereDecrypt(cipherText, key);
      break;
    case "base64":
      try {
        result = atob(cipherText);
      } catch {
        result = "Invalid Base64 string.";
      }
      break;
    case "rsa":
      result = await rsaDecrypt(cipherText);
      break;
    case "sha256":
      result = "SHA-256 is a one-way hash. Cannot decrypt.";
      break;
    default:
      result = "Invalid method";
  }

  document.getElementById("ciphertext").value = result;
}

function copyText() {
  const text = document.getElementById("ciphertext");
  text.select();
  text.setSelectionRange(0, 99999);
  document.execCommand("copy");
  alert("Copied to clipboard!");
}

async function decryptNewBox() {
  const cipherText = document.getElementById("cipherInput").value;
  const algo = document.getElementById("decryptAlgo").value;
  let key = "";

  if (!cipherText || !algo) {
    alert("Please enter ciphertext and select a method.");
    return;
  }

  if (algo === "caesar") key = document.getElementById("decryptCaesarKey").value;
  if (algo === "vigenere") key = document.getElementById("decryptVigenereKey").value;

  let result = "";

  switch (algo) {
    case "caesar":
      result = caesarCipherDecrypt(cipherText, key);
      break;
    case "vigenere":
      result = vigenereDecrypt(cipherText, key);
      break;
    case "base64":
      try {
        result = atob(cipherText);
      } catch {
        result = "Invalid Base64 string.";
      }
      break;
    case "rsa":
      result = await rsaDecrypt(cipherText);
      break;
    case "sha256":
      result = "SHA-256 is a one-way hash. Cannot decrypt.";
      break;
    default:
      result = "Invalid method selected.";
  }

  document.getElementById("decryptedOutput").value = result;
}

function copyDecryptedText() {
  const text = document.getElementById("decryptedOutput");
  text.select();
  text.setSelectionRange(0, 99999);
  document.execCommand("copy");
  alert("Decrypted text copied!");
}


function showSavedMessages() {
  const currentUser = localStorage.getItem("currentUser");
  if (!currentUser) return;

  const stored = JSON.parse(localStorage.getItem(currentUser + "_messages")) || [];
  let messageList = stored.map(msg => 
    `<li><strong>${msg.method}</strong>: ${msg.encrypted}</li>`).join("");
  document.getElementById("savedMessages").innerHTML = `<ul>${messageList}</ul>`;
}



window.onload = async () => {
  const user = localStorage.getItem("currentUser");
  if (user) {
    document.getElementById("loginBox").style.display = "none";
    document.getElementById("appContent").style.display = "block";
    

    await loadRSAKeys();
  }
};


async function loadRSAKeys() {
  const savedKeys = localStorage.getItem('rsaKeys');
  if (!savedKeys) return;
  
  try {
    const { publicKey, privateKey } = JSON.parse(savedKeys);
    rsaKeyPair = {
      publicKey: await crypto.subtle.importKey(
        "jwk", publicKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true, ["encrypt"]
      ),
      privateKey: await crypto.subtle.importKey(
        "jwk", privateKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true, ["decrypt"]
      )
    };
    console.log("RSA keys auto-loaded successfully");
  } catch (error) {
    console.error("Failed to load RSA keys:", error);
  }
}

function logout() {
  localStorage.removeItem("currentUser");
  localStorage.removeItem('rsaKeys'); 
  location.reload();
}
