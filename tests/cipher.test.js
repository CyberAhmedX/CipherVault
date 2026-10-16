// Unit tests for cipher.js, run with Node's built-in test runner: node --test tests/
// cipher.js uses only the Web Crypto API, which Node provides too, so the exact
// same code that runs in the browser is tested here.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

require('../cipher.js');
const CV = globalThis.CV;

const rejectsWith = (promise, message) =>
  assert.rejects(promise, err => err instanceof CV.CipherError && (!message || err.message.includes(message)));

// ---------- classical ciphers ----------

test('Caesar matches the textbook example and round-trips', () => {
  assert.equal(CV.caesar('Hello, World!', '3'), 'Khoor, Zruog!');
  assert.equal(CV.caesar('Khoor, Zruog!', '3', true), 'Hello, World!');
});

test('Caesar handles negative and large shifts', () => {
  assert.equal(CV.caesar('abc', '-1'), 'zab');
  assert.equal(CV.caesar('abc', '27'), 'bcd');
  assert.equal(CV.caesar(CV.caesar('Attack at dawn', '-5'), '-5', true), 'Attack at dawn');
});

test('Caesar rejects a shift that is not a whole number', () => {
  assert.throws(() => CV.caesar('abc', 'three'), CV.CipherError);
  assert.throws(() => CV.caesar('abc', '2.5'), CV.CipherError);
});

test('Vigenère matches the textbook example (ATTACKATDAWN / LEMON)', () => {
  assert.equal(CV.vigenere('ATTACKATDAWN', 'LEMON'), 'LXFOPVEFRNHR');
  assert.equal(CV.vigenere('LXFOPVEFRNHR', 'LEMON', true), 'ATTACKATDAWN');
});

test('Vigenère advances the keyword only on letters and keeps case', () => {
  assert.equal(CV.vigenere('Attack at dawn!', 'lemon'), 'Lxfopv ef rnhr!');
});

test('Vigenère rejects empty keywords and keywords with digits', () => {
  assert.throws(() => CV.vigenere('abc', ''), CV.CipherError);
  assert.throws(() => CV.vigenere('abc', 'key1'), CV.CipherError);
});

// ---------- encoding and hashing ----------

test('Base64 matches the standard encoding', () => {
  assert.equal(CV.base64Encode('hello'), 'aGVsbG8=');
  assert.equal(CV.base64Decode('aGVsbG8='), 'hello');
});

test('Base64 round-trips Urdu and emoji', () => {
  for (const text of ['سلام دنیا', 'CipherVault 🔐', '']) {
    assert.equal(CV.base64Decode(CV.base64Encode(text)), text);
  }
});

test('Base64 rejects invalid input and binary data', () => {
  assert.throws(() => CV.base64Decode('not base64!'), CV.CipherError);
  assert.throws(() => CV.base64Decode('/w=='), /binary data/);  // the single byte 0xFF is not UTF-8
});

test('Byte/Base64 helpers round-trip buffers larger than one chunk', () => {
  const bytes = new Uint8Array(100000).map((_, i) => i * 7);
  assert.deepEqual(CV.b64ToBytes(CV.bytesToB64(bytes)), bytes);
});

test('SHA-256 matches the official test vectors (FIPS 180-2)', async () => {
  assert.equal(await CV.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(await CV.sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('SHA-256 verify accepts the right hash, rejects a wrong one and bad input', async () => {
  const h = await CV.sha256Hex('message');
  assert.equal(await CV.sha256Verify('message', h.toUpperCase()), true);
  assert.equal(await CV.sha256Verify('Message', h), false);
  await rejectsWith(CV.sha256Verify('message', 'abc123'), '64 hexadecimal');
});

// ---------- RSA + AES hybrid ----------

test('RSA + AES hybrid encryption', async t => {
  const pair = await CV.generateRsaKeyPair();
  const other = await CV.generateRsaKeyPair();

  await t.test('uses a 3072-bit RSA-OAEP key with SHA-256', () => {
    assert.equal(pair.publicKey.algorithm.name, 'RSA-OAEP');
    assert.equal(pair.publicKey.algorithm.modulusLength, 3072);
    assert.equal(pair.publicKey.algorithm.hash.name, 'SHA-256');
  });

  await t.test('round-trips a message far longer than RSA alone allows', async () => {
    const long = 'Detected SQL injection in the nginx access log. '.repeat(400) + 'سلام 🔐';
    const ct = await CV.rsaEncrypt(long, pair.publicKey);
    assert.ok(ct.startsWith(CV.HYBRID_PREFIX));
    assert.equal(await CV.rsaDecrypt(ct, pair.privateKey), long);
  });

  await t.test('gives different output each time for the same message', async () => {
    const a = await CV.rsaEncrypt('same', pair.publicKey);
    const b = await CV.rsaEncrypt('same', pair.publicKey);
    assert.notEqual(a, b);
  });

  await t.test('refuses to decrypt with the wrong private key', async () => {
    const ct = await CV.rsaEncrypt('secret', pair.publicKey);
    await rejectsWith(CV.rsaDecrypt(ct, other.privateKey), 'different key');
  });

  await t.test('detects a changed ciphertext (AES-GCM authentication)', async () => {
    const ct = await CV.rsaEncrypt('secret', pair.publicKey);
    const bytes = CV.b64ToBytes(ct.slice(CV.HYBRID_PREFIX.length));
    bytes[bytes.length - 1] ^= 1;  // flip one bit of the GCM tag
    await rejectsWith(CV.rsaDecrypt(CV.HYBRID_PREFIX + CV.bytesToB64(bytes), pair.privateKey), 'was changed');
  });

  await t.test('reports a truncated message clearly', async () => {
    const ct = await CV.rsaEncrypt('secret', pair.publicKey);
    await rejectsWith(CV.rsaDecrypt(ct.slice(0, 40), pair.privateKey), 'incomplete');
  });

  await t.test('still decrypts the first version format (plain RSA-OAEP)', async () => {
    const legacy = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pair.publicKey, new TextEncoder().encode('old message'));
    assert.equal(await CV.rsaDecrypt(CV.bytesToB64(new Uint8Array(legacy)), pair.privateKey), 'old message');
  });

  await t.test('exported keys import back and still decrypt', async () => {
    const { publicJwk, privateJwk } = await CV.exportRsaPair(pair);
    const again = await CV.importRsaPair(JSON.stringify(publicJwk), JSON.stringify(privateJwk));
    const ct = await CV.rsaEncrypt('backup works', again.publicKey);
    assert.equal(await CV.rsaDecrypt(ct, pair.privateKey), 'backup works');
    assert.equal(await CV.fingerprint(again.publicKey), await CV.fingerprint(pair.publicKey));
  });

  await t.test('rejects keys that are not a matching RSA pair', async () => {
    const a = await CV.exportRsaPair(pair);
    const b = await CV.exportRsaPair(other);
    await rejectsWith(CV.importRsaPair(a.publicJwk, b.privateJwk), 'not a matching pair');
    await rejectsWith(CV.importRsaPair(a.privateJwk, a.privateJwk), 'not an RSA public key');
    await rejectsWith(CV.importRsaPair('not json', '{}'), 'JWK');
  });

  await t.test('fingerprint is 16 colon-separated hex pairs and differs between keys', async () => {
    const fp = await CV.fingerprint(pair.publicKey);
    assert.match(fp, /^([0-9A-F]{2}:){15}[0-9A-F]{2}$/);
    assert.notEqual(fp, await CV.fingerprint(other.publicKey));
  });
});

// ---------- the vault ----------

test('The vault', async t => {
  const salt = CV.newSalt();
  const key = await CV.deriveVaultKey('correct horse battery staple', salt);

  await t.test('uses 600,000 PBKDF2 iterations and a 16-byte random salt', () => {
    assert.equal(CV.PBKDF2_ITERATIONS, 600000);
    assert.equal(salt.length, 16);
    assert.notDeepEqual(CV.newSalt(), salt);
  });

  await t.test('the derived key cannot be exported', async () => {
    assert.equal(key.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('raw', key));
  });

  await t.test('seals and unseals data', async () => {
    const data = { messages: [{ method: 'rsa', output: 'CV1:...' }], note: 'سلام' };
    assert.deepEqual(await CV.unseal(key, await CV.seal(key, data)), data);
  });

  await t.test('uses a fresh IV for every save', async () => {
    const a = await CV.seal(key, { x: 1 });
    const b = await CV.seal(key, { x: 1 });
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.data, b.data);
  });

  await t.test('never stores the data in readable form', async () => {
    const sealed = await CV.seal(key, { secret: 'my original message' });
    assert.ok(!JSON.stringify(sealed).includes('my original message'));
    assert.ok(!atob(sealed.data).includes('my original message'));
  });

  await t.test('a wrong passphrase cannot open the vault', async () => {
    const sealed = await CV.seal(key, { x: 1 });
    const wrong = await CV.deriveVaultKey('wrong passphrase', salt);
    await rejectsWith(CV.unseal(wrong, sealed), 'Wrong passphrase');
  });

  await t.test('the same passphrase with a different salt cannot open the vault', async () => {
    const sealed = await CV.seal(key, { x: 1 });
    const otherSalt = await CV.deriveVaultKey('correct horse battery staple', CV.newSalt());
    await rejectsWith(CV.unseal(otherSalt, sealed));
  });

  await t.test('tampered vault data is rejected', async () => {
    const sealed = await CV.seal(key, { x: 1 });
    const bytes = CV.b64ToBytes(sealed.data);
    bytes[0] ^= 1;
    await rejectsWith(CV.unseal(key, { iv: sealed.iv, data: CV.bytesToB64(bytes) }));
  });
});
