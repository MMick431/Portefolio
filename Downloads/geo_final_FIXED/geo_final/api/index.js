// Point d'entrée Vercel — importe ton server.js existant
// Vercel attend un export "app" Express, pas app.listen()

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const crypto   = require("crypto");
const path     = require("path");
const { Resend } = require("resend");

const app = express();

// ======================================
//   CONFIGURATION SÉCURITÉ
// ======================================

const sessions = new Map();
const SESSION_DURATION = 2 * 60 * 60 * 1000;

const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || "admin@geoapplestore.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "geo2025admin";
const ADMIN_SECRET_PATH = process.env.ADMIN_SECRET_PATH || "gestion-prive-x7k2m9";

// ======================================
//   MIDDLEWARES
// ======================================

app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",
  methods: ["GET", "POST"],
}));

// ======================================
//   RATE LIMITING
// ======================================

const requestCounts = new Map();
function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip  = req.headers["x-forwarded-for"] || req.connection.remoteAddress || "unknown";
    const key = `${ip}-${req.path}`;
    const now = Date.now();
    const data = requestCounts.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > data.resetAt) { data.count = 0; data.resetAt = now + windowMs; }
    data.count++;
    requestCounts.set(key, data);
    if (data.count > maxRequests) {
      return res.status(429).json({ success: false, error: "Trop de requêtes. Réessayez dans quelques minutes." });
    }
    next();
  };
}

// ======================================
//   UTILITAIRES
// ======================================

function sanitize(str, maxLen = 500) {
  return String(str || "")
    .replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;")
    .replace(/`/g, "&#x60;").trim().slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// ======================================
//   BLOQUER FICHIERS SENSIBLES
// ======================================

app.get(["/server.js", "/api/index.js", "/package.json", "/package-lock.json", "/.env"], (req, res) => {
  res.status(403).send("Accès interdit.");
});

// ======================================
//   AUTHENTIFICATION ADMIN
// ======================================

function requireAdminSession(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token) return res.status(401).json({ success: false, error: "Non autorisé." });
  const session = sessions.get(token);
  if (!session || Date.now() > session.expiresAt) {
    sessions.delete(token);
    return res.status(401).json({ success: false, error: "Session expirée. Reconnectez-vous." });
  }
  session.expiresAt = Date.now() + SESSION_DURATION;
  next();
}

const loginAttempts = new Map();

app.post("/api/admin/login", rateLimit(5, 15 * 60 * 1000), (req, res) => {
  const { email, password } = req.body;
  const ip = req.headers["x-forwarded-for"] || "unknown";
  if (!email || !password) return res.status(400).json({ success: false, error: "Champs manquants." });

  const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  if (Date.now() < attempts.lockedUntil) {
    const wait = Math.ceil((attempts.lockedUntil - Date.now()) / 1000 / 60);
    return res.status(429).json({ success: false, error: `Trop de tentatives. Attendez ${wait} minute(s).` });
  }

  const emailMatch    = email.trim().toLowerCase() === ADMIN_EMAIL.toLowerCase();
  const passwordMatch = password === ADMIN_PASSWORD;

  if (!emailMatch || !passwordMatch) {
    attempts.count++;
    if (attempts.count >= 5) { attempts.lockedUntil = Date.now() + 15 * 60 * 1000; attempts.count = 0; }
    loginAttempts.set(ip, attempts);
    return res.status(401).json({ success: false, error: "Email ou mot de passe incorrect." });
  }

  loginAttempts.delete(ip);
  const token = generateToken();
  sessions.set(token, { email: ADMIN_EMAIL, createdAt: Date.now(), expiresAt: Date.now() + SESSION_DURATION, ip });
  res.json({ success: true, token, expiresIn: SESSION_DURATION });
});

app.post("/api/admin/logout", (req, res) => {
  const token = req.headers["x-admin-token"];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

app.get("/api/admin/check", requireAdminSession, (req, res) => {
  res.json({ success: true, email: ADMIN_EMAIL });
});

// ======================================
//   PAGE ADMIN
// ======================================

app.get(`/${ADMIN_SECRET_PATH}`, (req, res) => {
  res.sendFile(path.join(process.cwd(), "admin-secure.html"));
});

app.get("/admin.html", (req, res) => res.status(404).send("Page non trouvée."));

// ======================================
//   FICHIERS STATIQUES
// ======================================

app.use(express.static(path.join(process.cwd()), { index: "index.html" }));

// ======================================
//   ROUTE : COMMANDE NEUF
// ======================================

app.post("/api/send-order", rateLimit(8, 60 * 60 * 1000), async (req, res) => {
  const { customerName, customerPhone, customerEmail, customerAddress,
          productName, productPrice, color, storage, notes, cartItems, isCart, orderDate } = req.body;

  if (!customerName || !customerPhone || !customerEmail || !productName)
    return res.status(400).json({ success: false, error: "Champs obligatoires manquants." });
  if (!isValidEmail(customerEmail))
    return res.status(400).json({ success: false, error: "Email invalide." });

  const sName    = sanitize(customerName, 100);
  const sPhone   = sanitize(customerPhone, 30);
  const sEmail   = sanitize(customerEmail, 254);
  const sAddress = sanitize(customerAddress, 300);
  const sProduct = sanitize(productName, 200);
  const sPrice   = sanitize(String(productPrice), 50);
  const sColor   = sanitize(color, 50);
  const sStorage = sanitize(storage, 50);
  const sNotes   = sanitize(notes, 1000);
  const sCart    = sanitize(cartItems, 2000);
  const sDate    = sanitize(orderDate, 100);

  const waNum = process.env.WHATSAPP_NUMBER || "22943924728";
  const waMsg = encodeURIComponent(`Bonjour ${sName}, j'ai bien reçu votre commande pour ${sProduct}. Je reviens vers vous rapidement ! - GEO APPLE STORE`);

  const cartSection = isCart && sCart ? `
    <tr><td style="padding:12px 0;">
      <p style="margin:0 0 8px;color:#aaa;font-size:12px;text-transform:uppercase;">Détails du panier</p>
      <div style="background:#111;border-radius:8px;padding:12px;font-family:monospace;font-size:13px;color:#ccc;white-space:pre-line;">${sCart}</div>
    </td></tr>` : "";

  const html = buildEmailHTML({ type: "neuf", sName, sPhone, sEmail, sAddress, sProduct, sPrice, sColor, sStorage, sNotes, cartSection, sDate, waNum, waMsg });

  try {
    const resend = new Resend(process.env.RESEND_API_KEY);
    const data = await resend.emails.send({
      from: "GEO Apple Store <onboarding@resend.dev>",
      to: [process.env.STORE_EMAIL || "michaelhologan45@gmail.com"],
      subject: `Nouvelle commande — ${sProduct} | GEO APPLE STORE`,
      html,
      reply_to: sEmail,
    });
    res.json({ success: true, emailId: data.id });
  } catch (error) {
    console.error("Erreur Resend:", error);
    res.status(500).json({ success: false, error: "Erreur envoi email." });
  }
});

// ======================================
//   ROUTE : COMMANDE OCCASION
// ======================================

app.post("/api/send-order-occasion", rateLimit(8, 60 * 60 * 1000), async (req, res) => {
  const { customerName, customerPhone, customerEmail, customerAddress,
          productName, productPrice, notes, orderDate } = req.body;

  if (!customerName || !customerPhone || !customerEmail || !productName)
    return res.status(400).json({ success: false, error: "Champs obligatoires manquants." });
  if (!isValidEmail(customerEmail))
    return res.status(400).json({ success: false, error: "Email invalide." });

  const sName    = sanitize(customerName, 100);
  const sPhone   = sanitize(customerPhone, 30);
  const sEmail   = sanitize(customerEmail, 254);
  const sAddress = sanitize(customerAddress, 300);
  const sProduct = sanitize(productName, 200);
  const sPrice   = sanitize(String(productPrice), 50);
  const sNotes   = sanitize(notes, 1000);
  const sDate    = sanitize(orderDate, 100);

  const waNum = process.env.WHATSAPP_NUMBER || "22943924728";
  const waMsg = encodeURIComponent(`Bonjour ${sName}, j'ai bien reçu votre commande pour ${sProduct}. Je reviens vers vous rapidement ! - GEO APPLE STORE`);

  const html = buildEmailHTML({ type: "occasion", sName, sPhone, sEmail, sAddress, sProduct, sPrice, sNotes, sDate, waNum, waMsg });

  try {
    const resend = new Resend(process.env.RESEND_API_KEY);
    const data = await resend.emails.send({
      from: "GEO Apple Store <onboarding@resend.dev>",
      to: [process.env.STORE_EMAIL || "michaelhologan45@gmail.com"],
      subject: `Commande Occasion — ${sProduct} | GEO APPLE STORE`,
      html,
      reply_to: sEmail,
    });
    res.json({ success: true, emailId: data.id });
  } catch (error) {
    console.error("Erreur Resend occasion:", error);
    res.status(500).json({ success: false, error: "Erreur envoi email." });
  }
});

// ======================================
//   EMAIL HTML
// ======================================

function buildEmailHTML({ type, sName, sPhone, sEmail, sAddress, sProduct, sPrice, sColor, sStorage, sNotes, cartSection, sDate, waNum, waMsg }) {
  const isOccasion = type === "occasion";
  const grad   = isOccasion ? "linear-gradient(135deg,#b87000,#e8a000)" : "linear-gradient(135deg,#e8001d,#a00015)";
  const accent = isOccasion ? "#e8a000" : "#e8001d";
  const titre  = isOccasion ? "Commande Occasion" : "Nouvelle Commande";

  const extras = isOccasion ? "" : `
    <p style="margin:8px 0 0;color:#aaa;font-size:14px;">Couleur: ${sColor || "—"} &nbsp;|&nbsp; Stockage: ${sStorage || "—"}</p>
    ${cartSection || ""}`;

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#141414;border-radius:20px;border:1px solid #222;">
      <tr><td style="background:${grad};padding:36px 40px;text-align:center;">
        <p style="margin:0;color:rgba(0,0,0,0.5);font-size:12px;letter-spacing:3px;text-transform:uppercase;">${titre}</p>
        <h1 style="margin:8px 0 0;color:#000;font-size:26px;font-weight:900;letter-spacing:2px;">GEO APPLE STORE</h1>
      </td></tr>
      <tr><td style="padding:24px 40px;">
        <p style="margin:0 0 8px;color:#888;font-size:11px;text-transform:uppercase;">Produit</p>
        <p style="margin:0;color:#fff;font-size:18px;font-weight:700;">${sProduct}</p>
        <p style="margin:6px 0 0;color:${accent};font-size:22px;font-weight:900;">${sPrice} FCFA</p>
        ${extras}
      </td></tr>
      <tr><td style="padding:0 40px 24px;">
        <p style="margin:0 0 8px;color:#888;font-size:11px;text-transform:uppercase;">Client</p>
        <p style="margin:0;color:#fff;font-size:15px;font-weight:600;">${sName}</p>
        <p style="margin:4px 0;color:#25d366;font-size:14px;">${sPhone}</p>
        <p style="margin:4px 0;color:#58a6ff;font-size:14px;">${sEmail}</p>
        <p style="margin:4px 0;color:#ccc;font-size:13px;">${sAddress}</p>
        ${sNotes ? `<p style="margin:8px 0 0;color:#f0c040;font-size:13px;font-style:italic;">${sNotes}</p>` : ""}
      </td></tr>
      <tr><td style="padding:0 40px 30px;">
        <a href="https://wa.me/${waNum}?text=${waMsg}"
           style="display:block;background:#25d366;color:#fff;text-align:center;padding:16px;border-radius:12px;font-weight:700;font-size:15px;text-decoration:none;">
          Répondre via WhatsApp
        </a>
      </td></tr>
      <tr><td style="padding:20px 40px;border-top:1px solid #222;text-align:center;">
        <p style="margin:0;color:#555;font-size:12px;">Reçue le ${sDate} — GEO APPLE STORE</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

// ======================================
//   404
// ======================================

app.use((req, res) => res.status(404).send("Page non trouvée."));

// Export pour Vercel (pas de app.listen)
module.exports = app;
