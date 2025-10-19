<script>
/*
  MelonTec Client-Side Security Module (Demo)
  - PBKDF2 password derivation (Web Crypto)
  - AES-GCM per-user encryption of data stored in localStorage
  - RFC6238 TOTP implementation using HMAC-SHA1 (Web Crypto)
  - Constant-time compare, salts, random secrets
  - All functions return Promises
*/

/* ---------- Helpers ---------- */
const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function fromBase64(str){ return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }
function randBytes(len){
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}
function bufEq(a,b){ // constant-time
  if(a.byteLength !== b.byteLength) return false;
  const va = new Uint8Array(a), vb = new Uint8Array(b);
  let res = 0;
  for(let i=0;i<va.length;i++) res |= va[i] ^ vb[i];
  return res === 0;
}

/* ---------- PBKDF2 (derive key) ---------- */
async function deriveKeyPBKDF2(password, salt, iterations=200_000, keyLen=32){
  // returns raw key bytes (Uint8Array)
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveBits','deriveKey']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
    passKey,
    keyLen * 8
  );
  return new Uint8Array(derivedBits);
}

/* ---------- AES-GCM encrypt/decrypt ---------- */
async function aesGcmEncrypt(keyBytes, plainObj){
  const iv = randBytes(12);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const plain = enc.encode(JSON.stringify(plainObj));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plain);
  return { iv: toBase64(iv), ct: toBase64(ct) };
}
async function aesGcmDecrypt(keyBytes, encrypted){
  try{
    const iv = fromBase64(encrypted.iv);
    const ct = fromBase64(encrypted.ct);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return JSON.parse(dec.decode(plain));
  }catch(e){
    throw new Error('decryption_failed');
  }
}

/* ---------- Storage helpers ---------- */
function storeRaw(key, obj){ localStorage.setItem(key, JSON.stringify(obj)); }
function loadRaw(key){ const s = localStorage.getItem(key); return s ? JSON.parse(s) : null; }

/* ---------- Secure user record structure ----------
  Stored in localStorage under 'mt_users_v2'
  {
    "<username>": {
      salt: base64,
      pwHash: base64 (derived key),
      iterations: number,
      encParams: { // encrypted payload with AES-GCM (user metadata, secrets)
         iv, ct
      }
    }
  }
  The AES key used to encrypt encParams is derived from the PBKDF2 output but with a different info (HKDF would be ideal; here we use derived bytes directly).
------------------------------------------------------------------ */

const USER_STORE_KEY = 'mt_users_v2';

/* ---------- Create / Register ---------- */
async function secureRegister(username, password, metadata={email:''}){
  const users = loadRaw(USER_STORE_KEY) || {};
  if(users[username]) throw new Error('user_exists');

  const salt = randBytes(16);
  const iterations = 200_000;
  const derived = await deriveKeyPBKDF2(password, salt, iterations, 32); // 32 bytes
  // store derived key hash (we store it so login can compare) - but we don't store raw pw
  const pwHash = toBase64(derived);

  // initial encrypted payload: contains metadata, empty user data, 2FA secret null
  const encPayload = await aesGcmEncrypt(derived, { meta: metadata, data: { notes:[], mails:[], files:[], photos:[] }, twofa: { enabled:false, secret:null } });

  users[username] = {
    salt: toBase64(salt),
    iterations,
    pwHash,
    encPayload
  };
  storeRaw(USER_STORE_KEY, users);
  return true;
}

/* ---------- Login ---------- */
async function secureLogin(username, password){
  const users = loadRaw(USER_STORE_KEY) || {};
  const rec = users[username];
  if(!rec) throw new Error('no_user');

  const salt = fromBase64(rec.salt);
  const iterations = rec.iterations || 200_000;
  const derived = await deriveKeyPBKDF2(password, salt, iterations, 32);
  const derivedB64 = toBase64(derived);

  // constant-time compare
  if(!bufEq(derived, fromBase64(rec.pwHash))) throw new Error('invalid_credentials');

  // attempt to decrypt payload
  const payload = await aesGcmDecrypt(derived, rec.encPayload);
  // return an object containing derivedKeyBytes (for session), and payload
  return { key: derived, payload };
}

/* ---------- Save encrypted user payload ---------- */
async function saveEncryptedUserData(username, keyBytes, payloadObj){
  const users = loadRaw(USER_STORE_KEY) || {};
  const rec = users[username];
  if(!rec) throw new Error('no_user');

  const newEnc = await aesGcmEncrypt(keyBytes, payloadObj);
  rec.encPayload = newEnc;
  users[username] = rec;
  storeRaw(USER_STORE_KEY, users);
  return true;
}

/* ---------- TOTP (RFC6238) implementation ----------
   - generateSecretBase32()
   - verifyTotp(secretBase32, code)
   - generateTotpCode(secretBase32, time=now)
-------------------------------------------------------- */

/* base32 utils (RFC4648, no padding) */
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32ToBytes(base32){
  base32 = base32.replace(/=+$/,'').toUpperCase();
  let bits = 0, value = 0, index = 0;
  const output = [];
  for(let i=0;i<base32.length;i++){
    const idx = BASE32.indexOf(base32[i]);
    if(idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if(bits >= 8){
      output.push((value >>> (bits - 8)) & 0xFF);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
function bytesToHex(b){ return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(''); }
function intTo8Buffer(num){
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(4, num >>> 0);
  dv.setUint32(0, Math.floor(num / 2**32));
  return new Uint8Array(buf);
}

function generateSecretBase32(length=16){
  const bytes = randBytes(length);
  let bits = 0, value = 0;
  let output = '';
  for(let i=0;i<bytes.length;i++){
    value = (value << 8) | bytes[i];
    bits += 8;
    while(bits >= 5){
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if(bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}

async function hotp(secretBase32, counter){
  const keyBytes = base32ToBytes(secretBase32);
  // import key for HMAC-SHA1
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name:'HMAC', hash:'SHA-1'}, false, ['sign']);
  const counterBuf = intTo8Buffer(counter);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
  const sigBytes = new Uint8Array(sig);
  const offset = sigBytes[sigBytes.length - 1] & 0xf;
  const code = ((sigBytes[offset] & 0x7f) << 24) |
               ((sigBytes[offset+1] & 0xff) << 16) |
               ((sigBytes[offset+2] & 0xff) << 8) |
               (sigBytes[offset+3] & 0xff);
  return (code % 1_000_000).toString().padStart(6,'0');
}

async function totp(secretBase32, forTime = Date.now()){
  const step = 30;
  const t = Math.floor(forTime / 1000 / step);
  return await hotp(secretBase32, t);
}
async function verifyTotp(secretBase32, code, window=1){
  const now = Date.now();
  for(let i=-window;i<=window;i++){
    const c = await totp(secretBase32, now + i*30*1000);
    if(c === code) return true;
  }
  return false;
}

/* ---------- High-level flows for the demo UI ---------- */

/* Register wrapper: creates user and returns true/throws */
async function uiRegister(username, password, email){
  // validation
  if(!username || !password) throw new Error('invalid_input');
  return await secureRegister(username, password, { email });
}

/* Login wrapper: returns session { username, key, payload } */
async function uiLogin(username, password){
  return await secureLogin(username, password);
}

/* Setup TOTP for the logged-in user: returns secretBase32 (show to user as QR or string) */
async function uiSetupTotp(username, keyBytes){
  // generate secret and store in encrypted payload
  const users = loadRaw(USER_STORE_KEY) || {};
  const rec = users[username];
  if(!rec) throw new Error('no_user');
  // decrypt payload to get structure
  const payload = await aesGcmDecrypt(keyBytes, rec.encPayload);
  const secret = generateSecretBase32(20);
  payload.twofa = { enabled: true, secret };
  // re-encrypt and save
  await saveEncryptedUserData(username, keyBytes, payload);
  return secret; // show to user (QR can be generated using otpauth URL)
}

/* Verify 2FA code on login or sensitive action */
async function uiVerifyTotpForUser(username, keyBytes, code){
  const users = loadRaw(USER_STORE_KEY) || {};
  const rec = users[username];
  if(!rec) throw new Error('no_user');
  const payload = await aesGcmDecrypt(keyBytes, rec.encPayload);
  if(!payload.twofa || !payload.twofa.enabled) throw new Error('2fa_not_enabled');
  return await verifyTotp(payload.twofa.secret, code);
}

/* ---------- Example integration helpers (for your UI) ---------- */
/* These functions map to the earlier simple demo's functions names so you can plug them in:
   - call secureRegister -> on signup
   - call secureLogin -> on login; then set sessionKey = result.key and sessionPayload = result.payload
   - call saveEncryptedUserData(username, sessionKey, sessionPayload) after modifications
   - call uiSetupTotp(username, sessionKey) to enable 2FA (returns secret for user to scan)
*/

window.melonsec = {
  secureRegister,
  secureLogin,
  saveEncryptedUserData,
  loadRaw, storeRaw,
  uiSetupTotp,
  uiVerifyTotpForUser,
  totp, // expose for demo (generate current code)
  generateSecretBase32,
};

/* ---------- Usage examples (copy to your event handlers) ----------
  // Register:
  try {
    await melonsec.secureRegister('marlon', 'VeryStr0ngP@ss', { email:'m@x.com' });
    alert('registered');
  } catch(e){ alert(e.message); }

  // Login:
  try {
    const session = await melonsec.secureLogin('marlon','VeryStr0ngP@ss');
    // session.key = Uint8Array, session.payload = decrypted user payload
    window._session = session; window._username = 'marlon';
  } catch(e){ alert(e.message); }

  // Setup 2FA:
  const secret = await melonsec.uiSetupTotp(_username, _session.key);
  // show QR: otpauth://totp/MelonTec:${_username}?secret=${secret}&issuer=MelonTec

  // Verify 2FA:
  const ok = await melonsec.uiVerifyTotpForUser(_username, _session.key, '123456');
  // Save modified payload back:
  session.payload.data.notes.push('test');
  await melonsec.saveEncryptedUserData(_username, _session.key, session.payload);

------------------------------------------------------------------ */

</script>
