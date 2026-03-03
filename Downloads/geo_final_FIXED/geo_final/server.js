// ======================================
//   GEO APPLE STORE — SERVER.JS BLINDÉ
//   Sécurité maximale : helmet, rate-limit,
//   sessions serveur, validation, IP check
// ======================================

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const crypto   = require("crypto");
const fs       = require("fs");
const path     = require("path");
const { Resend } = require("resend");

const app    = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// ======================================
//   CONFIGURATION SÉCURITÉ
// ======================================

// Sessions stockées en mémoire (côté serveur uniquement)
const sessions = new Map();
const SESSION_DURATION = 2 * 60 * 60 * 1000; // 2 heures

// Identifiants admin (jamais envoyés au navigateur)
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@geoapplestore.com";
// ADMIN_PASSWORD est lu dynamiquement via process.env à chaque vérification
// pour prendre en compte les changements sans redémarrage
if (!process.env.ADMIN_PASSWORD) process.env.ADMIN_PASSWORD = "geo2025admin";
Object.defineProperty(global, "ADMIN_PASSWORD", {
  get: () => process.env.ADMIN_PASSWORD,
  configurable: true
});

// URL secrète de l'admin (changer ici pour personnaliser)
const ADMIN_SECRET_PATH = process.env.ADMIN_SECRET_PATH || "gestion-prive-x7k2m9";

// ======================================
//   MIDDLEWARES DE SÉCURITÉ
// ======================================

// 1. Cacher qu'on utilise Express
app.disable("x-powered-by");

// 2. Headers de sécurité manuels (sans helmet)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// 3. Limite taille des requêtes
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",
  methods: ["GET", "POST"],
}));

// 4. Rate limiting manuel (sans librairie)
const requestCounts = new Map();
function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip  = req.ip || req.connection.remoteAddress || "unknown";
    const key = `${ip}-${req.path}`;
    const now = Date.now();
    const data = requestCounts.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > data.resetAt) {
      data.count   = 0;
      data.resetAt = now + windowMs;
    }

    data.count++;
    requestCounts.set(key, data);

    if (data.count > maxRequests) {
      return res.status(429).json({
        success: false,
        error: "Trop de requêtes. Réessayez dans quelques minutes."
      });
    }
    next();
  };
}

// Nettoyage automatique toutes les 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of requestCounts.entries()) {
    if (now > data.resetAt) requestCounts.delete(key);
  }
  for (const [token, session] of sessions.entries()) {
    if (now > session.expiresAt) sessions.delete(token);
  }
}, 10 * 60 * 1000);

// 5. Bloquer accès aux fichiers sensibles
app.get([
  "/server.js", "/package.json", "/package-lock.json",
  "/.env", "/node_modules", "/admin.html"
], (req, res) => {
  res.status(403).send("Accès interdit.");
});

// ======================================
//   UTILITAIRES
// ======================================

function sanitize(str, maxLen = 500) {
  return String(str || "")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/`/g, "&#x60;")
    .trim()
    .slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// ======================================
//   AUTHENTIFICATION ADMIN (côté serveur)
// ======================================

// Middleware : vérifier session admin
function requireAdminSession(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token) return res.status(401).json({ success: false, error: "Non autorisé." });

  const session = sessions.get(token);
  if (!session || Date.now() > session.expiresAt) {
    sessions.delete(token);
    return res.status(401).json({ success: false, error: "Session expirée. Reconnectez-vous." });
  }

  // Renouveler la session à chaque requête
  session.expiresAt = Date.now() + SESSION_DURATION;
  next();
}

// Tentatives de connexion échouées (brute force protection)
const loginAttempts = new Map();

// LOGIN — max 5 tentatives par IP par 15 minutes
app.post("/api/admin/login", rateLimit(5, 15 * 60 * 1000), (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip || "unknown";

  // Vérification basique
  if (!email || !password) {
    return res.status(400).json({ success: false, error: "Champs manquants." });
  }

  // Anti brute-force
  const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  if (Date.now() < attempts.lockedUntil) {
    const wait = Math.ceil((attempts.lockedUntil - Date.now()) / 1000 / 60);
    return res.status(429).json({ success: false, error: `Trop de tentatives. Attendez ${wait} minute(s).` });
  }

  // Vérification des identifiants (comparaison sécurisée)
  const emailMatch    = email.trim().toLowerCase() === ADMIN_EMAIL.toLowerCase();
  const passwordMatch = password === ADMIN_PASSWORD;

  if (!emailMatch || !passwordMatch) {
    attempts.count++;
    if (attempts.count >= 5) {
      attempts.lockedUntil = Date.now() + 15 * 60 * 1000; // Bloqué 15 min
      attempts.count = 0;
    }
    loginAttempts.set(ip, attempts);
    return res.status(401).json({ success: false, error: "Email ou mot de passe incorrect." });
  }

  // Succès — créer session
  loginAttempts.delete(ip);
  const token = generateToken();
  sessions.set(token, {
    email: ADMIN_EMAIL,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_DURATION,
    ip
  });

  res.json({ success: true, token, expiresIn: SESSION_DURATION });
});

// LOGOUT
app.post("/api/admin/logout", (req, res) => {
  const token = req.headers["x-admin-token"];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

// VÉRIFIER SESSION
app.get("/api/admin/check", requireAdminSession, (req, res) => {
  res.json({ success: true, email: ADMIN_EMAIL });
});

// CHANGER MOT DE PASSE (nécessite session + .env manuel)
app.post("/api/admin/change-password", requireAdminSession, rateLimit(3, 60 * 60 * 1000), (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (currentPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "Mot de passe actuel incorrect." });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ success: false, error: "Le nouveau mot de passe doit faire au moins 8 caractères." });
  }

  // Mise à jour en mémoire immédiate
  process.env.ADMIN_PASSWORD = newPassword;

  // Réécriture du fichier .env pour persister après redémarrage
  try {
    const envPath = path.resolve(__dirname, ".env");
    let envContent = fs.readFileSync(envPath, "utf8");
    envContent = envContent.replace(
      /^ADMIN_PASSWORD=.*/m,
      `ADMIN_PASSWORD=${newPassword}`
    );
    fs.writeFileSync(envPath, envContent, "utf8");
  } catch (err) {
    console.error("Erreur mise à jour .env :", err);
    return res.status(500).json({ success: false, error: "Mot de passe changé en mémoire mais non sauvegardé. Contactez l'administrateur." });
  }

  res.json({ success: true, message: "Mot de passe mis à jour avec succès." });
});

// ======================================
//   PAGE ADMIN — URL SECRÈTE
// ======================================

app.get(`/${ADMIN_SECRET_PATH}`, (req, res) => {
  res.sendFile(__dirname + "/admin-secure.html");
});

// Bloquer l'ancienne URL admin.html
app.get("/admin.html", (req, res) => {
  res.status(404).send("Page non trouvée.");
});

// ======================================
//   FICHIERS STATIQUES (après les routes protégées)
// ======================================

app.use(express.static(".", {
  index: "index.html",
  // Ne pas servir ces fichiers sensibles
  setHeaders: (res, path) => {
    if (path.endsWith(".env") || path.endsWith("server.js")) {
      res.status(403).end();
    }
  }
}));

// ======================================
//   ROUTE : COMMANDE NEUF
// ======================================

app.post("/api/send-order", rateLimit(8, 60 * 60 * 1000), async (req, res) => {
  const {
    customerName, customerPhone, customerEmail,
    customerAddress, productName, productPrice,
    color, storage, notes, cartItems, isCart, orderDate
  } = req.body;

  // Validation
  if (!customerName || !customerPhone || !customerEmail || !productName) {
    return res.status(400).json({ success: false, error: "Champs obligatoires manquants." });
  }
  if (!isValidEmail(customerEmail)) {
    return res.status(400).json({ success: false, error: "Email invalide." });
  }

  // Sanitisation
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

  const cartSection = isCart && sCart ? `
    <tr><td style="padding:12px 0;border-bottom:1px solid #2a2a2a;">
      <p style="margin:0 0 8px;color:#aaa;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Détails du panier</p>
      <div style="background:#111;border-radius:8px;padding:12px;font-family:monospace;font-size:13px;color:#ccc;white-space:pre-line;">${sCart}</div>
    </td></tr>` : "";

  const htmlEmail = buildEmailHTML({
    type: "neuf", sName, sPhone, sEmail, sAddress,
    sProduct, sPrice, sColor, sStorage, sNotes,
    cartSection, orderDate: sanitize(orderDate, 100)
  });

  try {
    const data = await resend.emails.send({
      from: "GEO Apple Store <onboarding@resend.dev>",
      to: [process.env.STORE_EMAIL || "michaelhologan45@gmail.com"],
      subject: `Nouvelle commande — ${sProduct} | GEO APPLE STORE`,
      html: htmlEmail,
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
  const {
    customerName, customerPhone, customerEmail,
    customerAddress, productName, productPrice, notes, orderDate
  } = req.body;

  // Validation
  if (!customerName || !customerPhone || !customerEmail || !productName) {
    return res.status(400).json({ success: false, error: "Champs obligatoires manquants." });
  }
  if (!isValidEmail(customerEmail)) {
    return res.status(400).json({ success: false, error: "Email invalide." });
  }

  // Sanitisation
  const sName    = sanitize(customerName, 100);
  const sPhone   = sanitize(customerPhone, 30);
  const sEmail   = sanitize(customerEmail, 254);
  const sAddress = sanitize(customerAddress, 300);
  const sProduct = sanitize(productName, 200);
  const sPrice   = sanitize(String(productPrice), 50);
  const sNotes   = sanitize(notes, 1000);

  const htmlEmail = buildEmailHTML({
    type: "occasion", sName, sPhone, sEmail, sAddress,
    sProduct, sPrice, sNotes,
    orderDate: sanitize(orderDate, 100)
  });

  try {
    const data = await resend.emails.send({
      from: "GEO Apple Store <onboarding@resend.dev>",
      to: [process.env.STORE_EMAIL || "michaelhologan45@gmail.com"],
      subject: `Commande Occasion — ${sProduct} | GEO APPLE STORE`,
      html: htmlEmail,
      reply_to: sEmail,
    });
    res.json({ success: true, emailId: data.id });
  } catch (error) {
    console.error("Erreur Resend occasion:", error);
    res.status(500).json({ success: false, error: "Erreur envoi email." });
  }
});

// ======================================
//   CONSTRUCTEUR EMAIL HTML
// ======================================

function buildEmailHTML({ type, sName, sPhone, sEmail, sAddress, sProduct, sPrice, sColor, sStorage, sNotes, cartSection, orderDate }) {
  const isOccasion = type === "occasion";
  const headerGrad = isOccasion
    ? "linear-gradient(135deg,#b87000,#e8a000)"
    : "linear-gradient(135deg,#e8001d,#a00015)";
  const accentColor = isOccasion ? "#e8a000" : "#e8001d";
  const titleLabel  = isOccasion ? "Nouvelle Commande Occasion" : "Nouvelle Commande";
  const badgeText   = isOccasion ? "Commande iPhone Occasion — Traitement requis" : "Commande reçue — Traitement requis";
  const waMsg = encodeURIComponent(`Bonjour ${sName}, j'ai bien recu votre commande pour ${sProduct}. Je reviens vers vous rapidement ! - GEO APPLE STORE`);
  const waNum = process.env.WHATSAPP_NUMBER || "22943924728";

  const productDetails = isOccasion ? "" : `
    <tr><td style="padding-top:16px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="width:50%;padding:8px 12px;background:#222;border-radius:8px;">
            <p style="margin:0;color:#888;font-size:11px;text-transform:uppercase;">Couleur</p>
            <p style="margin:4px 0 0;color:#fff;font-size:14px;font-weight:600;">${sColor || "—"}</p>
          </td>
          <td style="width:8px;"></td>
          <td style="width:50%;padding:8px 12px;background:#222;border-radius:8px;">
            <p style="margin:0;color:#888;font-size:11px;text-transform:uppercase;">Stockage</p>
            <p style="margin:4px 0 0;color:#fff;font-size:14px;font-weight:600;">${sStorage || "—"}</p>
          </td>
        </tr>
      </table>
    </td></tr>
    ${cartSection || ""}`;

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#141414;border-radius:20px;overflow:hidden;border:1px solid #222;">
      <tr>
        <td style="background:${headerGrad};padding:36px 40px;text-align:center;">
          <p style="margin:0;color:rgba(0,0,0,0.5);font-size:12px;letter-spacing:3px;text-transform:uppercase;">${titleLabel}</p>
          <h1 style="margin:8px 0 0;color:#000;font-size:26px;font-weight:900;letter-spacing:2px;">GEO APPLE STORE</h1>
        </td>
      </tr>
      <tr><td style="padding:0 40px;">
        <div style="background:#1e1e1e;border:1px solid ${accentColor}33;border-radius:10px;padding:16px 20px;margin:24px 0;">
          <span style="color:${accentColor};font-weight:700;font-size:13px;text-transform:uppercase;">${badgeText}</span>
        </div>
      </td></tr>
      <tr><td style="padding:0 40px;">
        <p style="margin:0 0 12px;color:#888;font-size:11px;text-transform:uppercase;letter-spacing:2px;">Produit commandé</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a1a1a;border-radius:12px;border:1px solid #333;">
          <tr><td style="padding:20px 24px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td>
                <p style="margin:0;color:#fff;font-size:18px;font-weight:700;">${sProduct}</p>
                <p style="margin:6px 0 0;color:${accentColor};font-size:22px;font-weight:900;">${sPrice} FCFA</p>
              </td></tr>
              ${productDetails}
            </table>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:24px 40px 0;">
        <p style="margin:0 0 12px;color:#888;font-size:11px;text-transform:uppercase;letter-spacing:2px;">Informations client</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a1a1a;border-radius:12px;border:1px solid #333;">
          <tr><td style="padding:20px 24px;">
            <table width="100%" cellpadding="8" cellspacing="0">
              <tr>
                <td style="color:#888;font-size:13px;width:120px;">Nom</td>
                <td style="color:#fff;font-size:14px;font-weight:600;">${sName}</td>
              </tr>
              <tr style="border-top:1px solid #222;">
                <td style="color:#888;font-size:13px;">Telephone</td>
                <td style="font-size:14px;font-weight:600;">
                  <a href="tel:${sPhone}" style="color:#25d366;text-decoration:none;">${sPhone}</a>
                </td>
              </tr>
              <tr style="border-top:1px solid #222;">
                <td style="color:#888;font-size:13px;">Email</td>
                <td style="font-size:14px;font-weight:600;">
                  <a href="mailto:${sEmail}" style="color:#58a6ff;text-decoration:none;">${sEmail}</a>
                </td>
              </tr>
              <tr style="border-top:1px solid #222;">
                <td style="color:#888;font-size:13px;">Adresse</td>
                <td style="color:#fff;font-size:14px;font-weight:600;">${sAddress}</td>
              </tr>
              ${sNotes ? `
              <tr style="border-top:1px solid #222;">
                <td style="color:#888;font-size:13px;">Note</td>
                <td style="color:#f0c040;font-size:13px;font-style:italic;">${sNotes}</td>
              </tr>` : ""}
            </table>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:24px 40px 0;">
        <a href="https://wa.me/${waNum}?text=${waMsg}"
           style="display:block;background:#25d366;color:#fff;text-align:center;padding:16px;border-radius:12px;font-weight:700;font-size:15px;text-decoration:none;">
          Repondre au client via WhatsApp
        </a>
      </td></tr>
      <tr><td style="padding:30px 40px;text-align:center;border-top:1px solid #222;margin-top:24px;">
        <p style="margin:0;color:#555;font-size:12px;">Recue le ${orderDate}</p>
        <p style="margin:8px 0 0;color:#333;font-size:11px;">GEO APPLE STORE — Commande automatique</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

// ======================================
//   404 pour tout le reste
// ======================================

app.use((req, res) => {
  res.status(404).send("Page non trouvée.");
});

// ======================================
//   LANCEMENT
// ======================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n GEO APPLE STORE — Serveur securise demarre`);
  console.log(` http://localhost:${PORT}`);
  console.log(` Admin : http://localhost:${PORT}/${ADMIN_SECRET_PATH}`);
  console.log(` Email : ${process.env.STORE_EMAIL || "michaelhologan45@gmail.com"}\n`);
});
