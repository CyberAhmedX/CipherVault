/* CipherVault crypto core.
 * Pure functions, no page access, so they can be tested on their own.
 * Everything uses the browser's built-in Web Crypto API; no third-party crypto code.
 */
(function (root) {
  'use strict';

  const subtle = root.crypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  /** An error whose message is safe and useful to show the user. */
  class CipherError extends Error {}

  // ---------- bytes and Base64 ----------

  function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }

  function b64ToBytes(b64) {
    const s = atob(String(b64).replace(/\s+/g, ''));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  // ---------- classical ciphers ----------

  function parseShift(key) {
    const t = String(key).trim();
    if (!/^-?\d+$/.test(t)) throw new CipherError('Caesar shift must be a whole number, like 3 or -5.');
    return ((parseInt(t, 10) % 26) + 26) % 26;
  }

  function shiftLetter(c, s) {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + s) % 26 + base);
  }

  /** Caesar cipher. Letters A-Z only; everything else passes through. */
  function caesar(text, key, decrypt) {
    let s = parseShift(key);
    if (decrypt) s = (26 - s) % 26;
    return String(text).replace(/[A-Za-z]/g, c => shiftLetter(c, s));
  }

  function vigenereShifts(key) {
    const k = String(key).trim();
    if (!k) throw new CipherError('Enter a Vigenère keyword.');
    if (!/^[A-Za-z]+$/.test(k)) throw new CipherError('Vigenère keywords use letters only, like LEMON.');
    return Array.from(k.toLowerCase(), c => c.charCodeAt(0) - 97);
  }

  /** Vigenère cipher. The keyword advances only on letters, as in the classical cipher. */
  function vigenere(text, key, decrypt) {
    const shifts = vigenereShifts(key);
    let j = 0;
    return String(text).replace(/[A-Za-z]/g, c => {
      const s = shifts[j++ % shifts.length];
      return shiftLetter(c, decrypt ? (26 - s) % 26 : s);
    });
  }

  // ---------- encoding and hashing ----------

  /** Base64 of the UTF-8 bytes, so Urdu, emoji and any other text work. */
  function base64Encode(text) {
    return bytesToB64(encoder.encode(String(text)));
  }

  function base64Decode(b64) {
    const t = String(b64).trim();
    if (!/^[A-Za-z0-9+/\s]*={0,2}$/.test(t)) throw new CipherError('That is not valid Base64.');
    let bytes;
    try {
      bytes = b64ToBytes(t);
    } catch (e) {
      throw new CipherError('That is not valid Base64.');
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (e) {
      throw new CipherError('That Base64 decodes to binary data, not readable text.');
    }
  }

  async function sha256Hex(text) {
    const h = await subtle.digest('SHA-256', encoder.encode(String(text)));
    return Array.from(new Uint8Array(h), b => b.toString(16).padStart(2, '0')).join('');
  }

  /** True if text hashes to the given SHA-256 hex digest. */
  async function sha256Verify(text, hash) {
    const h = String(hash).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(h)) throw new CipherError('A SHA-256 hash is 64 hexadecimal characters.');
    return (await sha256Hex(text)) === h;
  }

  // ---------- RSA (hybrid with AES-GCM) ----------

  const RSA_ALGO = { name: 'RSA-OAEP', hash: 'SHA-256' };
  const HYBRID_PREFIX = 'CV1:';

  function generateRsaKeyPair() {
    return subtle.generateKey(
      Object.assign({ modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]) }, RSA_ALGO),
      true, ['encrypt', 'decrypt']);
  }

  async function exportRsaPair(pair) {
    return {
      publicJwk: await subtle.exportKey('jwk', pair.publicKey),
      privateJwk: await subtle.exportKey('jwk', pair.privateKey),
    };
  }

  /** Import a key pair from JWK objects or JSON text, and check the two halves belong together. */
  async function importRsaPair(publicJwk, privateJwk) {
    let pub, priv;
    try {
      pub = typeof publicJwk === 'string' ? JSON.parse(publicJwk) : publicJwk;
      priv = typeof privateJwk === 'string' ? JSON.parse(privateJwk) : privateJwk;
    } catch (e) {
      throw new CipherError('Keys must be JSON (JWK format), as shown by Export.');
    }
    if (!pub || pub.kty !== 'RSA' || !pub.n || pub.d) throw new CipherError('The public key is not an RSA public key in JWK format.');
    if (!priv || priv.kty !== 'RSA' || !priv.d) throw new CipherError('The private key is not an RSA private key in JWK format.');
    if (pub.n !== priv.n) throw new CipherError('These two keys are not a matching pair.');
    try {
      return {
        publicKey: await subtle.importKey('jwk', pub, RSA_ALGO, true, ['encrypt']),
        privateKey: await subtle.importKey('jwk', priv, RSA_ALGO, true, ['decrypt']),
      };
    } catch (e) {
      throw new CipherError('The browser rejected these keys. Check they were copied completely.');
    }
  }

  /** SHA-256 of the public key, shown as 16 colon-separated hex pairs. */
  async function fingerprint(publicKey) {
    const spki = await subtle.exportKey('spki', publicKey);
    const h = new Uint8Array(await subtle.digest('SHA-256', spki));
    return Array.from(h.slice(0, 16), b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
  }

  /**
   * Hybrid encryption: a fresh AES-256-GCM key encrypts the message, and RSA-OAEP encrypts that key.
   * RSA alone can only encrypt a few hundred bytes; this works for any length.
   * Output: "CV1:" + Base64( keyLength[2] | wrappedKey | iv[12] | ciphertext+tag )
   */
  async function rsaEncrypt(text, publicKey) {
    const aesKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoder.encode(String(text))));
    const raw = new Uint8Array(await subtle.exportKey('raw', aesKey));
    const wrapped = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw));
    const out = new Uint8Array(2 + wrapped.length + iv.length + ct.length);
    out[0] = wrapped.length >> 8;
    out[1] = wrapped.length & 0xff;
    out.set(wrapped, 2);
    out.set(iv, 2 + wrapped.length);
    out.set(ct, 2 + wrapped.length + iv.length);
    return HYBRID_PREFIX + bytesToB64(out);
  }

  async function rsaDecrypt(text, privateKey) {
    const t = String(text).trim();
    try {
      if (t.startsWith(HYBRID_PREFIX)) {
        const buf = b64ToBytes(t.slice(HYBRID_PREFIX.length));
        const n = (buf[0] << 8) | buf[1];
        if (buf.length < 2 + n + 12 + 16) throw new CipherError('This message is incomplete. Check it was copied in full.');
        const raw = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, buf.slice(2, 2 + n));
        const aesKey = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
        const plain = await subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(2 + n, 2 + n + 12) }, aesKey, buf.slice(2 + n + 12));
        return decoder.decode(plain);
      }
      // Messages from the first version of CipherVault: plain RSA-OAEP, no prefix
      return decoder.decode(await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, b64ToBytes(t)));
    } catch (e) {
      if (e instanceof CipherError) throw e;
      throw new CipherError('Could not decrypt. It was encrypted with a different key, or the text was changed.');
    }
  }

  // ---------- the vault: everything saved is encrypted with the passphrase ----------

  const PBKDF2_ITERATIONS = 600000;  // OWASP 2023 guidance for PBKDF2-HMAC-SHA256

  function newSalt() {
    return root.crypto.getRandomValues(new Uint8Array(16));
  }

  /** Turn a passphrase into an AES-256-GCM key. The key can't be exported, even by this app. */
  async function deriveVaultKey(passphrase, salt, iterations) {
    const base = await subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iterations || PBKDF2_ITERATIONS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  /** Encrypt a JS object for storage. A fresh random IV every time. */
  async function seal(key, data) {
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(data)));
    return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(ct)) };
  }

  /** Decrypt what seal() produced. GCM's tag check fails on a wrong passphrase or tampered data. */
  async function unseal(key, sealed) {
    try {
      const plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(sealed.iv) }, key, b64ToBytes(sealed.data));
      return JSON.parse(decoder.decode(plain));
    } catch (e) {
      throw new CipherError('Wrong passphrase.');
    }
  }

  root.CV = {
    CipherError, bytesToB64, b64ToBytes,
    caesar, vigenere, base64Encode, base64Decode, sha256Hex, sha256Verify,
    generateRsaKeyPair, exportRsaPair, importRsaPair, fingerprint, rsaEncrypt, rsaDecrypt, HYBRID_PREFIX,
    PBKDF2_ITERATIONS, newSalt, deriveVaultKey, seal, unseal,
  };
})(typeof window !== 'undefined' ? window : globalThis);
