/* server.js - MelonTec Cloud (demo, secure-by-default patterns) */
const express = require('express');
const helmet  = require('helmet');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csurf   = require('csurf');
const rateLimit = require('express-rate-limit');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const validator = require('validator');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const knexLib = require('knex');

// --- CONFIG (in prod move to env / KMS) ---
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_secret_in_prod';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'replace_refresh_secret';
const COOKIE_NAME = 'melontec_refresh';
const BCRYPT_ROUNDS = 12; // production: 12-14
const PORT = process.env.PORT || 3000;

// --- SIMPLE LOGGER ---
const logger = winston.createLogger({
  transports: [ new winston.transports.Console({ format: winston.format.simple() }) ]
});

// --- SIMPLE SQLITE DB via Knex (demo) ---
const knex = knexLib({
  client: 'sqlite3',
  connection: { filename: './data.sqlite3' },
  useNullAsDefault: true
});
// create tables if missing
(async ()=>{
  await knex.schema.hasTable('users').then(async(ex)=>{
    if(!ex){
      await knex.schema.createTable('users', t=>{
        t.increments('id').primary();
        t.string('uuid').unique();
        t.string('email').unique();
        t.string('password_hash');
        t.boolean('is_2fa_enabled').defaultTo(false);
        t.string('twofa_secret'); // encrypted in prod
        t.text('backup_codes'); // JSON array (hashed)
        t.text('refresh_token'); // store latest refresh token identifier
        t.timestamps(true,true);
      });
      logger.info('users table created');
    }
  });
})();

// --- APP ---
const app = express();

// security middlewares
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"]
    }
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Rate limiting ---
const generalLimiter = rateLimit({
  windowMs: 60*1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
});
const authLimiter = rateLimit({
  windowMs: 60*1000,
  max: 8, // stricter on auth endpoints
  message: { error: 'Too many requests, slow down' },
  standardHeaders: true
});
app.use(generalLimiter);

// --- CSRF protection for state-changing POSTs (we use double-submit for SPA too) ---
const csrfProtection = csurf({ cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' } });

// ------------------ "Two-layer firewall" (application) ------------------
// Layer 1: IP / blacklist / simple geo check (demo)
const ipBlocklist = new Set([ /* add blocked IPs */ ]);
app.use((req,res,next)=>{
  const ip = req.ip || req.connection.remoteAddress;
  if(ipBlocklist.has(ip)) return res.status(403).json({error:'forbidden'});
  // basic user agent / header sanity checks
  if(!req.headers['user-agent'] || req.headers['user-agent'].length < 10) {
    logger.warn('suspicious UA', {ip, ua: req.headers['user-agent']});
    return res.status(400).json({ error: 'bad request' });
  }
  next();
});

// Layer 2: payload inspection / WAF-like checks
app.use((req,res,next)=>{
  // basic SQLi/xss patterns (very simple demo) - in prod use real WAF
  const suspicious = /(\b(select|union|insert|delete|update|drop)\b|<script|onerror=|javascript:)/i;
  const bodyString = JSON.stringify(req.body || {});
  if(suspicious.test(bodyString)) {
    logger.warn('Blocked suspicious payload', { ip: req.ip, payload: bodyString.slice(0,200) });
    return res.status(400).json({ error: 'malicious payload detected' });
  }
  next();
});

// ------------------ Auth helpers ------------------
function signAccessToken(user){
  return jwt.sign({ uid: user.uuid, email: user.email }, JWT_SECRET, { expiresIn: '15m' });
}
function signRefreshToken(user, jti){
  // jti = refresh token id (store server-side)
  return jwt.sign({ uid: user.uuid, jti }, JWT_REFRESH_SECRET, { expiresIn: '30d' });
}

// safe cookie options
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
  // no maxAge here; token itself carries expiry
};

// ------------------ Routes ------------------

// health
app.get('/health', (req,res)=> res.json({ ok:true }));

// get CSRF token (for forms)
app.get('/csrf-token', csrfProtection, (req,res)=>{
  res.json({ csrfToken: req.csrfToken() });
});

// register
app.post('/api/register', authLimiter, async (req,res)=>{
  try{
    const { email, password } = req.body;
    if(!validator.isEmail(email) || !validator.isLength(password, { min: 8 })) {
      return res.status(400).json({ error: 'invalid registration data' });
    }
    const exists = await knex('users').where({ email }).first();
    if(exists) return res.status(400).json({ error: 'user exists' });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const uuid = uuidv4();
    await knex('users').insert({ uuid, email, password_hash: hash });
    logger.info('user registered', {email});
    res.json({ ok: true, message: 'registered' });
  }catch(err){
    logger.error('register err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// login -> returns access token & sets refresh cookie if 2FA not required or after 2FA verify
app.post('/api/login', authLimiter, async (req,res)=>{
  try{
    const { email, password } = req.body;
    if(!validator.isEmail(email)) return res.status(400).json({ error: 'invalid' });

    const user = await knex('users').where({ email }).first();
    if(!user) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).json({ error: 'invalid credentials' });

    // if 2FA enabled -> require TOTP step
    if(user.is_2fa_enabled){
      // create a temporary short-lived session token for 2FA verification (not JWT here - simple)
      const tmp = jwt.sign({ uid: user.uuid }, JWT_SECRET, { expiresIn: '5m' });
      return res.json({ twofa_required: true, tmp_token: tmp, message: 'enter 2FA code' });
    }

    // else create tokens and set refresh cookie
    const access = signAccessToken(user);
    const refreshId = uuidv4(); // jti
    const refresh = signRefreshToken(user, refreshId);

    // store refresh id server-side (rotate)
    await knex('users').where({ id: user.id }).update({ refresh_token: refreshId });

    res.cookie(COOKIE_NAME, refresh, cookieOptions);
    res.json({ accessToken: access });
  }catch(err){
    logger.error('login err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// verify 2FA
app.post('/api/2fa/verify', authLimiter, async (req,res)=>{
  try{
    const { tmp_token, code } = req.body;
    if(!tmp_token || !code) return res.status(400).json({ error:'bad' });
    let payload;
    try { payload = jwt.verify(tmp_token, JWT_SECRET); } catch(e){ return res.status(401).json({ error: 'expired' }); }
    const user = await knex('users').where({ uuid: payload.uid }).first();
    if(!user) return res.status(401).json({ error:'not found' });
    const secret = user.twofa_secret;
    if(!secret) return res.status(400).json({ error: '2FA not configured' });

    const valid = authenticator.check(code, secret);
    if(!valid) return res.status(401).json({ error: 'invalid 2FA' });

    // success: issue tokens
    const access = signAccessToken(user);
    const refreshId = uuidv4();
    const refresh = signRefreshToken(user, refreshId);
    await knex('users').where({ id: user.id }).update({ refresh_token: refreshId });

    res.cookie(COOKIE_NAME, refresh, cookieOptions);
    logger.info('2fa success', { email: user.email });
    res.json({ accessToken: access });
  }catch(e){
    logger.error('2fa err', e);
    res.status(500).json({ error: 'server error' });
  }
});

// enable 2FA (generate secret and QR) - user must be authenticated (demo: simple password verify)
app.post('/api/2fa/setup', authLimiter, async (req,res)=>{
  try{
    const { email, password } = req.body;
    const user = await knex('users').where({ email }).first();
    if(!user) return res.status(401).json({ error:'invalid' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).json({ error:'invalid' });

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.email, 'MelonTec', secret);
    const qrDataUrl = await QRCode.toDataURL(otpauth);

    // generate backup codes (store hashed)
    const backups = [];
    for(let i=0;i<8;i++){
      const code = Math.random().toString(36).slice(2).toUpperCase().slice(0,8);
      backups.push(code);
    }
    // store hashed backup codes and secret - in prod encrypt twofa_secret with KMS
    const hashedBackups = await Promise.all(backups.map(c=> bcrypt.hash(c, 10)));
    await knex('users').where({ id: user.id }).update({
      twofa_secret: secret,
      backup_codes: JSON.stringify(hashedBackups),
      is_2fa_enabled: true
    });

    res.json({ qr: qrDataUrl, backup_codes: backups }); // show raw backup codes *once*
  }catch(e){
    logger.error('2fa setup err', e);
    res.status(500).json({ error: 'server error' });
  }
});

// refresh token endpoint (rotate)
app.post('/api/token/refresh', async (req,res)=>{
  try{
    const token = req.cookies[COOKIE_NAME];
    if(!token) return res.status(401).json({ error: 'no token' });
    let payload;
    try { payload = jwt.verify(token, JWT_REFRESH_SECRET); } catch(e){ return res.status(401).json({ error: 'invalid refresh' }); }
    const user = await knex('users').where({ uuid: payload.uid }).first();
    if(!user) return res.status(401).json({ error:'no user' });
    // verify jti matches server stored refresh id
    if(payload.jti !== user.refresh_token) return res.status(401).json({ error:'token mismatch' });

    const newJti = uuidv4();
    const newRefresh = signRefreshToken(user, newJti);
    await knex('users').where({ id: user.id }).update({ refresh_token: newJti });

    const access = signAccessToken(user);
    res.cookie(COOKIE_NAME, newRefresh, cookieOptions);
    res.json({ accessToken: access });
  }catch(e){
    logger.error('refresh err', e);
    res.status(500).json({ error:'server error' });
  }
});

// logout - revoke refresh
app.post('/api/logout', async (req,res)=>{
  try{
    const token = req.cookies[COOKIE_NAME];
    if(token){
      let payload;
      try { payload = jwt.verify(token, JWT_REFRESH_SECRET); } catch(e){ payload=null; }
      if(payload){
        await knex('users').where({ uuid: payload.uid }).update({ refresh_token: null });
      }
    }
    res.clearCookie(COOKIE_NAME, cookieOptions);
    res.json({ ok:true });
  }catch(e){
    logger.error('logout err', e);
    res.status(500).json({ error:'server error' });
  }
});

// PROTECTED demo endpoint
app.get('/api/profile', async (req,res)=>{
  // access token passed in Authorization: Bearer <token>
  const auth = (req.headers.authorization || '').split(' ')[1];
  if(!auth) return res.status(401).json({ error:'no token' });
  try{
    const payload = jwt.verify(auth, JWT_SECRET);
    const user = await knex('users').where({ uuid: payload.uid }).first();
    if(!user) return res.status(404).json({ error:'not found' });
    res.json({ email: user.email, is_2fa_enabled: !!user.is_2fa_enabled });
  }catch(e){
    return res.status(401).json({ error: 'invalid token' });
  }
});

// start server
app.listen(PORT, ()=> {
  logger.info(`MelonTec Cloud demo listening on ${PORT}`);
});
