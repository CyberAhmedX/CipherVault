/* CipherVault interface. All cryptography lives in cipher.js (window.CV). */
(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const STORE_KEY = 'cipherVault.v1';
  const IDLE_LIMIT_MS = 10 * 60 * 1000;

  const METHODS = {
    rsa:      { name: 'RSA + AES', badge: 'Secure',    tone: 'ok',    enc: 'Encrypt', dec: 'Decrypt', desc: 'Public-key encryption for messages of any length.' },
    vigenere: { name: 'Vigenère',  badge: 'Classical', tone: 'warn',  enc: 'Encrypt', dec: 'Decrypt', desc: 'Keyword cipher. Breakable by hand; good for learning.' },
    caesar:   { name: 'Caesar',    badge: 'Classical', tone: 'warn',  enc: 'Encrypt', dec: 'Decrypt', desc: 'Shifts every letter. Only 25 possible keys.' },
    base64:   { name: 'Base64',    badge: 'Encoding',  tone: 'muted', enc: 'Encode',  dec: 'Decode',  desc: 'Not encryption. Anyone can decode it.' },
    sha256:   { name: 'SHA-256',   badge: 'Hash',      tone: 'info',  enc: 'Hash',    dec: 'Verify',  desc: 'One-way fingerprint. Verify it; it can’t be decrypted.' },
  };
  const ORDER = ['rsa', 'vigenere', 'caesar', 'base64', 'sha256'];

  /* While unlocked: { key, salt, iterations, data: { messages, rsa }, rsa: { publicKey, privateKey } | null, fp } */
  let vault = null;
  const ui = { enc: 'rsa', dec: 'rsa', lastEncSaved: true, lastActivity: Date.now() };

  // ---------- small helpers ----------

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  const errText = e => (e instanceof CV.CipherError ? e.message : 'Something went wrong: ' + (e && e.message ? e.message : e));
  const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
  const plural = (n, w) => `${n.toLocaleString()} ${w}${n === 1 ? '' : 's'}`;

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 2800);
  }

  async function copyText(text, what) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      // Older browsers: copy through a hidden textarea
      const ta = el('textarea'); ta.value = text; ta.setAttribute('readonly', '');
      ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.append(ta); ta.select();
      try { document.execCommand('copy'); } catch (_) { /* ignore */ }
      ta.remove();
    }
    toast(`${what} copied`);
  }

  function busy(btn, label) {
    const old = btn.textContent;
    btn.disabled = true; btn.classList.add('busy'); btn.textContent = label;
    return () => { btn.disabled = false; btn.classList.remove('busy'); btn.textContent = old; };
  }

  /** Two-step button: the first click arms it, the second (within 4 s) runs the action. */
  function armable(btn, armedLabel, action) {
    let timer = null;
    const normal = btn.textContent;
    btn.addEventListener('click', () => {
      if (!btn.classList.contains('armed')) {
        btn.classList.add('armed'); btn.textContent = armedLabel;
        timer = setTimeout(() => { btn.classList.remove('armed'); btn.textContent = normal; }, 4000);
        return;
      }
      clearTimeout(timer); btn.classList.remove('armed'); btn.textContent = normal;
      action();
    });
  }

  // ---------- storage ----------

  function readStore() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY)); } catch (e) { return null; }
  }

  async function persist() {
    const sealed = await CV.seal(vault.key, vault.data);
    localStorage.setItem(STORE_KEY, JSON.stringify({
      version: 1,
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: vault.iterations, salt: CV.bytesToB64(vault.salt) },
      iv: sealed.iv, data: sealed.data,
    }));
  }

  /** Data the first version of CipherVault left in localStorage without encryption. */
  function findLegacy() {
    const found = { messages: [], rsa: null, keys: [] };
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!/_messages$/.test(k)) continue;
        found.keys.push(k);
        let list = [];
        try { list = JSON.parse(localStorage.getItem(k)) || []; } catch (e) { /* unreadable: just delete it */ }
        for (const m of Array.isArray(list) ? list : []) {
          if (m && METHODS[m.method] && typeof m.encrypted === 'string' && !/^(En|De)cryption error/.test(m.encrypted)) {
            found.messages.push({ id: newId(), method: m.method, output: m.encrypted, created: null });
          }
        }
      }
      const rk = localStorage.getItem('rsaKeys');
      if (rk !== null) {
        found.keys.push('rsaKeys');
        try {
          const j = JSON.parse(rk);
          if (j && j.publicKey && j.privateKey) found.rsa = { publicJwk: j.publicKey, privateJwk: j.privateKey };
        } catch (e) { /* unreadable */ }
      }
      for (const k of ['authToken', 'currentUser']) if (localStorage.getItem(k) !== null) found.keys.push(k);
    } catch (e) { /* storage blocked */ }
    return found;
  }

  /** Move old unencrypted data into the vault, then delete the plaintext copies. */
  async function migrateLegacy() {
    const old = findLegacy();
    if (!old.keys.length) return;
    let movedKey = false;
    if (old.rsa && !vault.data.rsa) {
      try {
        await CV.importRsaPair(old.rsa.publicJwk, old.rsa.privateJwk);
        vault.data.rsa = old.rsa; movedKey = true;
      } catch (e) { /* invalid old key: skip it */ }
    }
    vault.data.messages = old.messages.concat(vault.data.messages);
    await persist();                                   // save encrypted first...
    old.keys.forEach(k => localStorage.removeItem(k)); // ...then delete the plaintext
    const parts = [];
    if (old.messages.length) parts.push(plural(old.messages.length, 'saved result'));
    if (movedKey) parts.push('your RSA key pair');
    toast(parts.length ? `Moved ${parts.join(' and ')} into the encrypted vault and deleted the unencrypted copies.`
                       : 'Deleted unencrypted data left by the old version.');
  }

  // ---------- lock screen ----------

  function buildDial() {
    const g = $('dial-ticks');
    const NS = 'http://www.w3.org/2000/svg';
    for (let i = 0; i < 60; i++) {
      const major = i % 5 === 0;
      const line = document.createElementNS(NS, 'line');
      line.setAttribute('x1', '100'); line.setAttribute('x2', '100');
      line.setAttribute('y1', major ? '14' : '18'); line.setAttribute('y2', '26');
      line.setAttribute('transform', `rotate(${i * 6} 100 100)`);
      line.setAttribute('class', major ? 'dial-tick major' : 'dial-tick');
      g.append(line);
    }
  }

  function showLock(reason) {
    const exists = !!readStore();
    $('app').hidden = true; $('session').hidden = true; $('lock').hidden = false;
    $('dial').classList.remove('open', 'turning');
    $('lock-erase').hidden = true; $('lock-erase-input').value = ''; $('lock-erase-btn').disabled = true;
    $('pass').value = ''; $('pass2').value = ''; $('lock-err').textContent = '';
    $('pass').classList.remove('bad'); $('pass2').classList.remove('bad');
    $('confirm-wrap').hidden = exists; $('pass-hint').hidden = exists; $('forgot').hidden = !exists;
    $('pass').autocomplete = exists ? 'current-password' : 'new-password';
    $('lock-title').textContent = exists ? 'Unlock your vault' : 'Create your vault';
    $('lock-lead').textContent = exists
      ? 'Enter your passphrase to decrypt your saved results and keys.'
      : 'Choose a passphrase. It encrypts everything CipherVault saves in this browser.';
    $('lock-submit').textContent = exists ? 'Unlock' : 'Create vault';
    $('lock-fine').textContent = exists
      ? 'Everything stays in this browser. Nothing is sent anywhere.'
      : 'There is no recovery. If you forget the passphrase, the vault cannot be opened, by you or anyone else.';
    const old = findLegacy();
    const legacy = $('legacy');
    if (old.messages.length || old.rsa) {
      const parts = [];
      if (old.messages.length) parts.push(plural(old.messages.length, 'saved result'));
      if (old.rsa) parts.push('an RSA key pair');
      legacy.textContent = `Found ${parts.join(' and ')} from the old version of CipherVault, stored without encryption. `
        + `${exists ? 'Unlocking' : 'Creating your vault'} moves them inside the encrypted vault and deletes the unencrypted copies.`;
      legacy.hidden = false;
    } else legacy.hidden = true;
    if (reason) toast(reason);
    setTimeout(() => $('pass').focus(), 50);
  }

  async function submitLock(e) {
    e.preventDefault();
    const stored = readStore();
    const pass = $('pass').value;
    const err = $('lock-err');
    err.textContent = '';
    $('pass').classList.remove('bad'); $('pass2').classList.remove('bad');

    if (!stored) {
      if (pass.length < 8) { err.textContent = 'Use at least 8 characters.'; $('pass').classList.add('bad'); return; }
      if (pass !== $('pass2').value) { err.textContent = 'The two passphrases don’t match.'; $('pass2').classList.add('bad'); return; }
    } else if (!pass) { err.textContent = 'Enter your passphrase.'; return; }

    const done = busy($('lock-submit'), stored ? 'Unlocking…' : 'Creating vault…');
    $('dial').classList.add('turning');
    try {
      if (!stored) {
        const salt = CV.newSalt();
        vault = { salt, iterations: CV.PBKDF2_ITERATIONS, key: await CV.deriveVaultKey(pass, salt, CV.PBKDF2_ITERATIONS),
                  data: { messages: [], rsa: null }, rsa: null, fp: '' };
        await persist();
      } else {
        const salt = CV.b64ToBytes(stored.kdf.salt);
        const key = await CV.deriveVaultKey(pass, salt, stored.kdf.iterations);
        const data = await CV.unseal(key, stored);
        vault = { salt, iterations: stored.kdf.iterations, key, data, rsa: null, fp: '' };
      }
      await migrateLegacy();
      await loadRsaFromVault();
      $('dial').classList.remove('turning'); $('dial').classList.add('open');
      setTimeout(enterApp, 500);
    } catch (ex) {
      vault = null;
      $('dial').classList.remove('turning');
      err.textContent = errText(ex);
      $('pass').classList.add('bad'); $('pass').select();
    } finally {
      done();
    }
  }

  function eraseVault() {
    localStorage.removeItem(STORE_KEY);
    vault = null;
    clearSensitiveFields();
    showLock('Vault erased.');
  }

  // ---------- session ----------

  function enterApp() {
    $('lock').hidden = true; $('app').hidden = false; $('session').hidden = false;
    $('pass').value = ''; $('pass2').value = '';
    $('kdf-iter').textContent = vault.iterations.toLocaleString();
    ui.lastActivity = Date.now();
    selectTab('encrypt');
    renderAll();
    $('enc-input').focus();
  }

  function clearSensitiveFields() {
    for (const id of ['enc-input', 'enc-output', 'dec-input', 'dec-output', 'pass', 'pass2']) $(id).value = '';
    document.querySelectorAll('.keyzone input, #keys-body textarea, #keys-body input').forEach(i => { i.value = ''; });
    $('dec-verdict').hidden = true;
    for (const id of ['enc-copy', 'enc-save', 'dec-copy']) $(id).disabled = true;
    for (const id of ['enc-meta', 'dec-meta', 'enc-err', 'dec-err']) $(id).textContent = '';
    $('keys-body').textContent = ''; $('vault-items').textContent = '';
  }

  function lockVault(reason) {
    vault = null;           // drop the key and decrypted data from memory
    clearSensitiveFields();
    showLock(reason);
  }

  function noteActivity() { ui.lastActivity = Date.now(); }
  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(ev => document.addEventListener(ev, noteActivity, { passive: true }));
  setInterval(() => {
    if (vault && Date.now() - ui.lastActivity > IDLE_LIMIT_MS) lockVault('Locked after 10 minutes without activity.');
  }, 15000);

  // ---------- RSA key handling ----------

  async function loadRsaFromVault() {
    vault.rsa = null; vault.fp = '';
    if (!vault.data.rsa) return;
    vault.rsa = await CV.importRsaPair(vault.data.rsa.publicJwk, vault.data.rsa.privateJwk);
    vault.fp = await CV.fingerprint(vault.rsa.publicKey);
  }

  async function createKeyPair() {
    const pair = await CV.generateRsaKeyPair();
    vault.data.rsa = Object.assign(await CV.exportRsaPair(pair), { created: Date.now() });
    await persist();
    await loadRsaFromVault();
  }

  function rsaBits() {
    const n = vault.data.rsa && vault.data.rsa.publicJwk.n;
    return n ? Math.floor(n.length * 6 / 8) * 8 : 0;  // base64url length -> bytes -> bits
  }

  // ---------- tabs ----------

  const TABS = ['encrypt', 'decrypt', 'vault', 'keys'];
  function selectTab(name) {
    for (const t of TABS) {
      const on = t === name;
      $('tab-' + t).setAttribute('aria-selected', String(on));
      $('tab-' + t).tabIndex = on ? 0 : -1;
      $('panel-' + t).hidden = !on;
    }
    if (name === 'vault') renderVault();
    if (name === 'keys') renderKeys();
  }
  TABS.forEach((t, i) => {
    $('tab-' + t).addEventListener('click', () => selectTab(t));
    $('tab-' + t).addEventListener('keydown', e => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const next = TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length];
      selectTab(next); $('tab-' + next).focus();
    });
  });

  // ---------- method pickers and key fields ----------

  function buildMethods(side) {
    const box = $(side + '-methods');
    for (const m of ORDER) {
      const meta = METHODS[m];
      const label = el('label', 'method');
      const input = el('input');
      input.type = 'radio'; input.name = side + '-method'; input.value = m; input.id = `${side}-m-${m}`;
      input.checked = m === ui[side];
      input.addEventListener('change', () => { ui[side] = m; renderKeyZone(side); });
      const card = el('span', 'card');
      const name = el('span', 'name', meta.name);
      name.append(el('span', 'badge ' + meta.tone, meta.badge));
      card.append(name, el('span', 'desc', meta.desc));
      label.append(input, card);
      box.append(label);
    }
  }

  // Key inputs are created once per side and shown or hidden, so values survive switching methods
  function buildKeyZone(side) {
    const zone = $(side + '-key');
    const field = (id, labelText, placeholder, mode) => {
      const wrap = el('div'); wrap.dataset.for = id;
      const lab = el('label', 'label', labelText); lab.htmlFor = `${side}-${id}`;
      const inp = el('input', 'field'); inp.id = `${side}-${id}`; inp.placeholder = placeholder;
      inp.autocomplete = 'off'; inp.spellcheck = false;
      if (mode) inp.inputMode = mode;
      wrap.append(lab, inp);
      zone.append(wrap);
    };
    field('caesar', 'Shift (a whole number, can be negative)', '3', 'numeric');
    field('vigenere', 'Keyword (letters only)', 'LEMON');
    if (side === 'dec') field('hash', 'Expected SHA-256 hash', '64 hexadecimal characters');
    const note = el('p', 'note'); note.id = side + '-note';
    zone.append(note);
  }

  function renderKeyZone(side) {
    const m = ui[side];
    const zone = $(side + '-key');
    for (const w of zone.querySelectorAll('[data-for]')) {
      const f = w.dataset.for;
      w.hidden = !((f === 'caesar' && m === 'caesar') || (f === 'vigenere' && m === 'vigenere') || (f === 'hash' && m === 'sha256' && side === 'dec'));
    }
    const note = $(side + '-note');
    note.textContent = '';
    if (m === 'rsa') {
      if (vault && vault.rsa) {
        note.append(side === 'enc' ? 'Encrypts with your public key. Fingerprint ' : 'Decrypts with your private key. Fingerprint ');
        note.append(el('span', 'fp', vault.fp));
      } else if (side === 'enc') {
        note.append('A ', el('b', '', '3072-bit RSA key pair'), ' is created for you the first time you encrypt.');
      } else {
        note.append('You have no key pair yet. Encrypt something first, or import a key pair in the Keys tab.');
      }
    } else if (m === 'base64') {
      note.textContent = 'Base64 is encoding, not encryption. Use it to make text safe to paste, never to keep it secret.';
    } else if (m === 'sha256' && side === 'enc') {
      note.textContent = 'The same text always gives the same 64-character hash, and the hash can’t be turned back into the text.';
    } else if (m === 'caesar' || m === 'vigenere') {
      note.textContent = 'Classical ciphers are broken. Fine for puzzles and learning, not for real secrets.';
    }
    note.hidden = !note.textContent;

    $(side + '-run').textContent = METHODS[m][side];
    if (side === 'dec') {
      const verify = m === 'sha256';
      $('dec-input-label').textContent = verify ? 'Original text' : (m === 'base64' ? 'Base64 text' : 'Encrypted text');
      $('dec-input').placeholder = verify ? 'Paste the text to check against the hash' : 'Paste the text to ' + METHODS[m].dec.toLowerCase();
      $('dec-output').hidden = verify;
      $('dec-copy').hidden = verify;
      if (!verify) $('dec-verdict').hidden = true;
    }
  }

  function renderAll() {
    renderKeyZone('enc'); renderKeyZone('dec');
    $('vault-count').textContent = vault ? vault.data.messages.length : 0;
  }

  const countChars = side => { $(side + '-count').textContent = plural($(side + '-input').value.length, 'character'); };

  // ---------- encrypt ----------

  async function runEncrypt() {
    const m = ui.enc;
    const text = $('enc-input').value;
    const err = $('enc-err');
    err.textContent = '';
    if (!text) { err.textContent = 'Type a message first.'; $('enc-input').focus(); return; }
    const done = busy($('enc-run'), m === 'rsa' && !vault.rsa ? 'Creating key pair…' : METHODS[m].enc + '…');
    try {
      let out;
      if (m === 'caesar') out = CV.caesar(text, $('enc-caesar').value);
      else if (m === 'vigenere') out = CV.vigenere(text, $('enc-vigenere').value);
      else if (m === 'base64') out = CV.base64Encode(text);
      else if (m === 'sha256') out = await CV.sha256Hex(text);
      else {
        if (!vault.rsa) { await createKeyPair(); renderAll(); toast('Created your RSA key pair. Back it up from the Keys tab.'); }
        out = await CV.rsaEncrypt(text, vault.rsa.publicKey);
      }
      $('enc-output').value = out;
      $('enc-meta').textContent = `${METHODS[m].name} · ${plural(out.length, 'character')}`;
      $('enc-copy').disabled = false; $('enc-save').disabled = false;
      ui.lastEncMethod = m;
    } catch (e) {
      err.textContent = errText(e);
    } finally {
      done();
    }
  }

  async function saveResult() {
    const output = $('enc-output').value;
    if (!output) return;
    vault.data.messages.unshift({ id: newId(), method: ui.lastEncMethod, output, created: Date.now() });
    await persist();
    $('enc-save').disabled = true;
    renderAll();
    toast('Saved to vault, encrypted');
  }

  // ---------- decrypt ----------

  async function runDecrypt() {
    const m = ui.dec;
    const text = $('dec-input').value;
    const err = $('dec-err');
    err.textContent = '';
    $('dec-verdict').hidden = true;
    if (!text.trim() && m !== 'sha256') { err.textContent = 'Paste something to ' + METHODS[m].dec.toLowerCase() + ' first.'; $('dec-input').focus(); return; }
    const done = busy($('dec-run'), METHODS[m].dec + '…');
    try {
      if (m === 'sha256') {
        const match = await CV.sha256Verify(text, $('dec-hash').value);
        const v = $('dec-verdict');
        v.className = 'verdict ' + (match ? 'ok' : 'bad');
        v.textContent = match ? 'Match' : 'No match';
        v.append(el('small', '', match ? 'This text produces exactly that hash.' : 'This text does not produce that hash. Even a one-character change gives a completely different hash.'));
        v.hidden = false;
        $('dec-meta').textContent = 'SHA-256 verification';
        return;
      }
      let out;
      if (m === 'caesar') out = CV.caesar(text, $('dec-caesar').value, true);
      else if (m === 'vigenere') out = CV.vigenere(text, $('dec-vigenere').value, true);
      else if (m === 'base64') out = CV.base64Decode(text);
      else {
        if (!vault.rsa) throw new CV.CipherError('You have no RSA key pair. Import the key pair that encrypted this message in the Keys tab.');
        out = await CV.rsaDecrypt(text, vault.rsa.privateKey);
      }
      $('dec-output').value = out;
      $('dec-meta').textContent = `${METHODS[m].name} · ${plural(out.length, 'character')}`;
      $('dec-copy').disabled = false;
    } catch (e) {
      $('dec-output').value = ''; $('dec-copy').disabled = true; $('dec-meta').textContent = '';
      err.textContent = errText(e);
    } finally {
      done();
    }
  }

  function openInDecrypt(item) {
    selectTab('decrypt');
    ui.dec = item.method;
    $('dec-m-' + item.method).checked = true;
    renderKeyZone('dec');
    $('dec-output').value = ''; $('dec-copy').disabled = true; $('dec-err').textContent = ''; $('dec-meta').textContent = '';
    if (item.method === 'sha256') { $('dec-hash').value = item.output; $('dec-input').value = ''; $('dec-input').focus(); }
    else {
      $('dec-input').value = item.output;
      const keyField = item.method === 'caesar' ? 'dec-caesar' : item.method === 'vigenere' ? 'dec-vigenere' : 'dec-run';
      $(keyField).focus();
    }
    countChars('dec');
  }

  // ---------- vault list ----------

  function renderVault() {
    const list = $('vault-items');
    list.textContent = '';
    const items = vault.data.messages;
    if (!items.length) {
      list.append(el('li', 'empty', 'Nothing saved yet. Encrypt something, then press Save to vault.'));
      return;
    }
    for (const item of items) {
      const meta = METHODS[item.method] || METHODS.base64;
      const li = el('li', 'item');
      const head = el('div', 'item-head');
      head.append(el('span', 'badge ' + meta.tone, meta.name));
      head.append(el('span', 'meta', item.created ? new Date(item.created).toLocaleString() : 'From the old version'));
      const actions = el('div', 'item-actions');
      const copyB = el('button', 'btn', 'Copy'); copyB.type = 'button';
      copyB.addEventListener('click', () => copyText(item.output, 'Result'));
      const openB = el('button', 'btn', item.method === 'sha256' ? 'Verify' : METHODS[item.method].dec); openB.type = 'button';
      openB.addEventListener('click', () => openInDecrypt(item));
      const delB = el('button', 'btn danger', 'Delete'); delB.type = 'button';
      armable(delB, 'Confirm delete', async () => {
        vault.data.messages = vault.data.messages.filter(x => x.id !== item.id);
        await persist(); renderAll(); renderVault(); toast('Deleted');
      });
      actions.append(copyB, openB, delB);
      head.append(actions);
      const body = el('div', 'item-body', item.output);
      li.append(head, body);
      if (item.output.length > 180) {
        const more = el('button', 'link', 'Show all'); more.type = 'button';
        more.addEventListener('click', () => { li.classList.toggle('expanded'); more.textContent = li.classList.contains('expanded') ? 'Show less' : 'Show all'; });
        li.append(more);
      }
      list.append(li);
    }
  }

  // ---------- keys tab ----------

  function renderKeys() {
    const box = $('keys-body');
    box.textContent = '';
    const intro = el('div');
    intro.append(el('h2', '', 'Your RSA key pair'));
    intro.append(el('p', '', 'The public key encrypts, and only the matching private key can decrypt. Both are stored inside your encrypted vault, never in plain text.'));
    box.append(intro);

    if (!vault.rsa) {
      const card = el('div', 'keycard');
      card.append(el('strong', '', 'No key pair yet'));
      card.append(el('span', 'spec', 'One is created automatically the first time you use RSA + AES, or you can create or import one now.'));
      const row = el('div', 'row');
      const gen = el('button', 'btn primary', 'Create key pair'); gen.type = 'button';
      gen.addEventListener('click', async () => {
        const done = busy(gen, 'Creating…');
        try { await createKeyPair(); renderAll(); renderKeys(); toast('Key pair created'); } catch (e) { toast(errText(e)); done(); }
      });
      row.append(gen); card.append(row); box.append(card);
    } else {
      const card = el('div', 'keycard');
      card.append(el('span', 'label', 'Fingerprint (SHA-256 of the public key)'));
      card.append(el('span', 'fp', vault.fp));
      card.append(el('span', 'spec', `RSA-OAEP ${rsaBits()}-bit with SHA-256, plus a fresh AES-256-GCM key per message` +
        (vault.data.rsa.created ? ` · created ${new Date(vault.data.rsa.created).toLocaleDateString()}` : '')));
      box.append(card);

      // public key: safe to share
      const pub = el('div');
      pub.append(el('h3', '', 'Public key'));
      pub.append(el('p', '', 'Safe to share. Anyone with it can encrypt messages that only you can read.'));
      const pubTa = el('textarea', 'field area out'); pubTa.readOnly = true; pubTa.rows = 6; pubTa.id = 'pub-key';
      pubTa.value = JSON.stringify(vault.data.rsa.publicJwk, null, 2);
      pubTa.setAttribute('aria-label', 'Public key');
      const pubRow = el('div', 'row end');
      const pubCopy = el('button', 'btn', 'Copy public key'); pubCopy.type = 'button';
      pubCopy.addEventListener('click', () => copyText(pubTa.value, 'Public key'));
      pubRow.append(pubCopy); pub.append(pubTa, pubRow); box.append(pub);

      // private key: hidden until asked for
      const priv = el('div');
      priv.append(el('h3', '', 'Private key backup'));
      priv.append(el('p', '', 'Needed to decrypt on another device or after erasing the vault. Never share it.'));
      const reveal = el('button', 'btn', 'Show private key'); reveal.type = 'button'; reveal.id = 'reveal-private';
      const privWrap = el('div'); privWrap.hidden = true;
      privWrap.append(el('div', 'warnbox', 'Anyone who sees this key can read every message encrypted to you. Store the copy somewhere safe, such as a password manager.'));
      const privTa = el('textarea', 'field area out'); privTa.readOnly = true; privTa.rows = 6; privTa.id = 'priv-key';
      privTa.setAttribute('aria-label', 'Private key');
      const privRow = el('div', 'row end');
      const privCopy = el('button', 'btn', 'Copy private key'); privCopy.type = 'button';
      privCopy.addEventListener('click', () => copyText(privTa.value, 'Private key'));
      privRow.append(privCopy);
      privWrap.append(privTa, privRow);
      reveal.addEventListener('click', () => {
        const show = privWrap.hidden;
        privTa.value = show ? JSON.stringify(vault.data.rsa.privateJwk, null, 2) : '';
        privWrap.hidden = !show; reveal.textContent = show ? 'Hide private key' : 'Show private key';
      });
      priv.append(reveal, privWrap); box.append(priv);
    }

    // import
    const imp = el('div');
    imp.append(el('h3', '', 'Import a key pair'));
    imp.append(el('p', '', 'Paste both halves exactly as copied from CipherVault (JWK format).'));
    const cols = el('div', 'cols2');
    const mk = (id, label) => {
      const w = el('div'); const l = el('label', 'label', label); l.htmlFor = id;
      const t = el('textarea', 'field area out'); t.id = id; t.rows = 5; t.spellcheck = false;
      w.append(l, t); cols.append(w); return t;
    };
    const impPub = mk('import-public', 'Public key');
    const impPriv = mk('import-private', 'Private key');
    const impErr = el('p', 'err'); impErr.setAttribute('role', 'alert');
    const impRow = el('div', 'row end');
    const impBtn = el('button', 'btn', vault.rsa ? 'Replace my key pair' : 'Import key pair'); impBtn.type = 'button'; impBtn.id = 'import-btn';
    impRow.append(impBtn);
    imp.append(cols, impErr, impRow);
    if (vault.rsa) imp.append(el('div', 'warnbox', 'Replacing your key pair means messages encrypted to the current key can no longer be decrypted, unless you backed it up.'));
    const doImport = async () => {
      impErr.textContent = '';
      try {
        await CV.importRsaPair(impPub.value, impPriv.value);   // validates before anything changes
        vault.data.rsa = { publicJwk: JSON.parse(impPub.value), privateJwk: JSON.parse(impPriv.value), created: Date.now() };
        await persist(); await loadRsaFromVault(); renderAll(); renderKeys();
        toast('Key pair imported');
      } catch (e) { impErr.textContent = errText(e); }
    };
    if (vault.rsa) armable(impBtn, 'Click again to replace', doImport); else impBtn.addEventListener('click', doImport);
    box.append(imp);

    // regenerate
    if (vault.rsa) {
      const regen = el('div', 'danger-zone');
      regen.append(el('h3', '', 'Create a new key pair'));
      regen.append(el('p', '', 'The current private key is deleted. Back it up first if you have messages encrypted to it.'));
      const row = el('div', 'row');
      const btn = el('button', 'btn danger', 'Create new key pair'); btn.type = 'button'; btn.id = 'regen-btn';
      armable(btn, 'Click again to replace', async () => {
        const done = busy(btn, 'Creating…');
        try { await createKeyPair(); renderAll(); renderKeys(); toast('New key pair created'); } catch (e) { toast(errText(e)); done(); }
      });
      row.append(btn); regen.append(row); box.append(regen);
    }
  }

  // ---------- wire up ----------

  function start() {
    if (!window.CV || !window.crypto || !crypto.subtle) {
      document.body.textContent = 'CipherVault needs a modern browser with the Web Crypto API. Open index.html directly, or serve it over https or localhost.';
      return;
    }
    buildDial();
    buildMethods('enc'); buildMethods('dec');
    buildKeyZone('enc'); buildKeyZone('dec');

    $('lock-form').addEventListener('submit', submitLock);
    $('forgot').addEventListener('click', () => { $('lock-erase').hidden = false; $('forgot').hidden = true; $('lock-erase-input').focus(); });
    $('lock-erase-input').addEventListener('input', e => { $('lock-erase-btn').disabled = e.target.value !== 'ERASE'; });
    $('lock-erase-btn').addEventListener('click', eraseVault);
    $('lock-btn').addEventListener('click', () => lockVault('Vault locked.'));

    $('enc-run').addEventListener('click', runEncrypt);
    $('dec-run').addEventListener('click', runDecrypt);
    $('enc-copy').addEventListener('click', () => copyText($('enc-output').value, 'Result'));
    $('dec-copy').addEventListener('click', () => copyText($('dec-output').value, 'Result'));
    $('enc-save').addEventListener('click', saveResult);
    $('enc-input').addEventListener('input', () => countChars('enc'));
    $('dec-input').addEventListener('input', () => countChars('dec'));
    for (const side of ['enc', 'dec']) {
      $(side + '-input').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $(side + '-run').click(); });
    }
    $('erase-input').addEventListener('input', e => { $('erase-btn').disabled = e.target.value !== 'ERASE'; });
    $('erase-btn').addEventListener('click', () => { $('erase-input').value = ''; $('erase-btn').disabled = true; eraseVault(); });

    showLock();
  }

  start();
})();
