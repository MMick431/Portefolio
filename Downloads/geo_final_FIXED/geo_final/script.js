/* ======================================
   GEO APPLE STORE — SCRIPT.JS
   WhatsApp: +22943924728
   Email: michaelhologan45@gmail.com
   ====================================== */

// ===== CONFIG =====
const CONFIG = {
  whatsapp: "22943924728",
  email: "michaelhologan45@gmail.com",
  storeName: "GGS APPLE STORE"
};

// ===== STATE =====
let cart = [];
let currentProduct = { name: "", price: "" };
let testimonialsIndex = 0;

// ===== LOADER =====
window.addEventListener("load", () => {
  setTimeout(() => {
    const loader = document.getElementById("loader");
    loader.style.opacity = "0";
    loader.style.transform = "scale(1.05)";
    loader.style.transition = "opacity 0.5s ease, transform 0.5s ease";
    setTimeout(() => { loader.style.display = "none"; }, 500);
  }, 1800);
});

// ===== CUSTOM CURSOR =====
const cursorDot = document.querySelector(".cursor-dot");
const cursorRing = document.querySelector(".cursor-ring");
let mouseX = 0, mouseY = 0, ringX = 0, ringY = 0;

document.addEventListener("mousemove", (e) => {
  mouseX = e.clientX; mouseY = e.clientY;
  cursorDot.style.left = mouseX + "px";
  cursorDot.style.top = mouseY + "px";
});

function animateCursor() {
  ringX += (mouseX - ringX) * 0.12;
  ringY += (mouseY - ringY) * 0.12;
  cursorRing.style.left = ringX + "px";
  cursorRing.style.top = ringY + "px";
  requestAnimationFrame(animateCursor);
}
animateCursor();

document.querySelectorAll("a, button, .product-card, .color-dot, .filter-btn").forEach(el => {
  el.addEventListener("mouseenter", () => document.body.classList.add("cursor-hover"));
  el.addEventListener("mouseleave", () => document.body.classList.remove("cursor-hover"));
});

// ===== HEADER SCROLL =====
window.addEventListener("scroll", () => {
  const header = document.getElementById("header");
  if (window.scrollY > 80) {
    header.classList.add("scrolled");
  } else {
    header.classList.remove("scrolled");
  }
});

// ===== MOBILE MENU =====
const hamburger = document.getElementById("hamburger");
const mobileMenu = document.getElementById("mobileMenu");

hamburger.addEventListener("click", () => {
  hamburger.classList.toggle("open");
  mobileMenu.classList.toggle("open");
});

function closeMobileMenu() {
  hamburger.classList.remove("open");
  mobileMenu.classList.remove("open");
}

// ===== SCROLL TO PRODUCTS =====
function scrollToProducts() {
  document.getElementById("products").scrollIntoView({ behavior: "smooth" });
}

// ===== REVEAL ON SCROLL =====
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      setTimeout(() => { entry.target.classList.add("visible"); }, i * 80);
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll(".product-card, .feature-card, .testimonial-card, .contact-item").forEach(el => {
  el.classList.add("reveal");
  revealObserver.observe(el);
});

// ===== FILTER PRODUCTS =====
function filterProducts(filter) {
  const cards = document.querySelectorAll(".product-card");
  const btns = document.querySelectorAll(".filter-btn");

  btns.forEach(btn => {
    btn.classList.toggle("active", btn.dataset.filter === filter);
  });

  cards.forEach(card => {
    if (filter === "all" || card.dataset.serie === filter) {
      card.classList.remove("hidden");
    } else {
      card.classList.add("hidden");
    }
  });
}

document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => filterProducts(btn.dataset.filter));
});

// ===== COLOR DOTS =====
document.querySelectorAll(".color-dot").forEach(dot => {
  dot.addEventListener("click", function() {
    const siblings = this.closest(".card-colors").querySelectorAll(".color-dot");
    siblings.forEach(d => d.classList.remove("selected"));
    this.classList.add("selected");
  });
});

// ===== CART =====
function openCart() {
  document.getElementById("cartPanel").classList.add("open");
  document.getElementById("cartOverlay").classList.add("open");
}

function closeCart() {
  document.getElementById("cartPanel").classList.remove("open");
  document.getElementById("cartOverlay").classList.remove("open");
}

document.getElementById("cartBtn").addEventListener("click", openCart);

function addToCart(name, price) {
  const existing = cart.find(item => item.name === name);
  if (existing) {
    existing.qty++;
  } else {
    cart.push({ name, price: parseInt(price), qty: 1 });
  }
  updateCartUI();
  showCartToast(name);
}

function removeFromCart(index) {
  cart.splice(index, 1);
  updateCartUI();
}

function updateCartUI() {
  const cartCount = document.getElementById("cartCount");
  const cartBody = document.getElementById("cartBody");
  const cartFooter = document.getElementById("cartFooter");
  const cartTotal = document.getElementById("cartTotal");

  const total = cart.reduce((sum, item) => sum + item.price * item.qty, 0);
  const totalCount = cart.reduce((sum, item) => sum + item.qty, 0);

  cartCount.textContent = totalCount;
  cartCount.style.display = totalCount > 0 ? "flex" : "none";
  cartTotal.textContent = total.toLocaleString("fr-FR") + " FCFA";
  cartFooter.style.display = cart.length > 0 ? "flex" : "none";

  if (cart.length === 0) {
    cartBody.innerHTML = `<div class="cart-empty"><i class="fas fa-bag-shopping"></i><p>Votre panier est vide</p></div>`;
  } else {
    cartBody.innerHTML = cart.map((item, i) => `
      <div class="cart-item">
        <div class="cart-item-name">${item.name} ${item.qty > 1 ? `<span style="color:var(--red);font-size:0.75rem">x${item.qty}</span>` : ""}</div>
        <div class="cart-item-price">${(item.price * item.qty).toLocaleString("fr-FR")} FCFA</div>
        <button class="cart-item-remove" onclick="removeFromCart(${i})"><i class="fas fa-xmark"></i></button>
      </div>
    `).join("");
  }
}

document.querySelectorAll(".btn-add-cart").forEach(btn => {
  btn.addEventListener("click", () => addToCart(btn.dataset.name, btn.dataset.price));
});

// Cart checkout button
document.getElementById("cartCheckoutBtn").addEventListener("click", () => {
  if (cart.length === 0) return;
  const itemsList = cart.map(item => `• ${item.name} x${item.qty} — ${(item.price * item.qty).toLocaleString("fr-FR")} FCFA`).join("\n");
  const total = cart.reduce((sum, item) => sum + item.price * item.qty, 0);
  const productName = "Panier: " + cart.map(i => i.name).join(", ");
  currentProduct = { name: productName, price: total.toLocaleString("fr-FR") + " FCFA", cartItems: itemsList, isCart: true };
  closeCart();
  openOrderModalWithProduct(productName, total.toLocaleString("fr-FR") + " FCFA");
});

function showCartToast(name) {
  const toast = document.createElement("div");
  toast.style.cssText = `
    position:fixed; bottom:100px; right:24px; z-index:5000;
    background:#1a1a1a; border:1px solid rgba(232,0,29,0.4);
    border-radius:12px; padding:12px 20px;
    font-family:'Montserrat',sans-serif; font-size:0.82rem;
    color:#fff; display:flex; align-items:center; gap:10px;
    animation:slideInRight 0.4s ease;
    box-shadow:0 8px 24px rgba(0,0,0,0.4);
  `;
  toast.innerHTML = `<i class="fas fa-check" style="color:#e8001d"></i> <span><strong>${name}</strong> ajouté au panier</span>`;
  document.body.appendChild(toast);

  const style = document.createElement("style");
  style.textContent = `@keyframes slideInRight{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}`;
  document.head.appendChild(style);

  setTimeout(() => {
    toast.style.opacity = "0"; toast.style.transform = "translateX(100px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

// ===== ORDER MODAL =====
function openOrderModal(btn) {
  const name = btn.dataset.name;
  const price = btn.dataset.price;
  openOrderModalWithProduct(name, price);
}

function openOrderModalWithProduct(name, price) {
  currentProduct = { name, price };
  document.getElementById("modalProductName").textContent = `${name} — ${price}`;
  document.getElementById("orderModalOverlay").classList.add("open");
  document.body.style.overflow = "hidden";
}

function closeOrderModal(e) {
  if (!e || e.target === document.getElementById("orderModalOverlay") || e.currentTarget?.classList?.contains("modal-close")) {
    document.getElementById("orderModalOverlay").classList.remove("open");
    document.body.style.overflow = "";
  }
}

// Attach close to modal-close buttons
document.querySelector(".modal-close").addEventListener("click", closeOrderModal);

// ===== SEND ORDER VIA WHATSAPP =====
document.getElementById("sendWhatsapp").addEventListener("click", () => {
  const name = document.getElementById("o-name").value.trim();
  const phone = document.getElementById("o-phone").value.trim();
  const email = document.getElementById("o-email").value.trim();
  const address = document.getElementById("o-address").value.trim();
  const color = document.getElementById("o-color").value;
  const storage = document.getElementById("o-storage").value;
  const notes = document.getElementById("o-notes").value.trim();

  if (!name || !phone || !email || !address) {
    shakeForm(); return;
  }

  const cartDetails = currentProduct.cartItems
    ? `\n━━━━━━━━━━━━━━━━━━━━\n📦 *DÉTAIL DU PANIER:*\n${currentProduct.cartItems}\n`
    : "";

  const now = new Date();
  const dateStr = now.toLocaleDateString("fr-FR", { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const timeStr = now.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });

  const message = encodeURIComponent(
    `╔══════════════════════╗\n` +
    `   🍎 *GEO APPLE STORE*  \n` +
    `    📦 NOUVELLE COMMANDE   \n` +
    `╚══════════════════════╝\n\n` +
    `━━━━━━━━━━━━━━━━━━━━\n` +
    `📱 *PRODUIT:*\n` +
    `   ${currentProduct.name}\n\n` +
    `💰 *PRIX TOTAL:* ${currentProduct.price} FCFA\n` +
    `🎨 *Couleur:* ${color}\n` +
    `💾 *Stockage:* ${storage}\n` +
    cartDetails +
    `\n━━━━━━━━━━━━━━━━━━━━\n` +
    `👤 *INFORMATIONS CLIENT:*\n` +
    `   📛 Nom       : ${name}\n` +
    `   📞 Téléphone : ${phone}\n` +
    `   📧 Email     : ${email}\n` +
    `   📍 Adresse   : ${address}\n` +
    (notes ? `   📝 Note      : ${notes}\n` : "") +
    `\n━━━━━━━━━━━━━━━━━━━━\n` +
    `⏰ *Date :* ${dateStr}\n` +
    `🕐 *Heure:* ${timeStr}\n\n` +
    `✅ _Commande passée via GGS APPLE STORE_\n` +
    `🌐 _Site web officiel_`
  );

  const url = `https://wa.me/${CONFIG.whatsapp}?text=${message}`;
  window.open(url, "_blank");

  closeOrderModal({ target: null, currentTarget: { classList: { contains: () => true } } });
  showConfirmModal(name, currentProduct.name, currentProduct.price, color, storage, address, "WhatsApp");
});

// ===== SEND ORDER VIA EMAIL (RESEND API) =====
document.getElementById("sendEmail").addEventListener("click", async () => {
  const name = document.getElementById("o-name").value.trim();
  const phone = document.getElementById("o-phone").value.trim();
  const email = document.getElementById("o-email").value.trim();
  const address = document.getElementById("o-address").value.trim();
  const color = document.getElementById("o-color").value;
  const storage = document.getElementById("o-storage").value;
  const notes = document.getElementById("o-notes").value.trim();

  if (!name || !phone || !email || !address) {
    shakeForm(); return;
  }

  // Afficher état de chargement sur le bouton
  const btn = document.getElementById("sendEmail");
  const originalHTML = btn.innerHTML;
  btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Envoi en cours...`;
  btn.disabled = true;

  try {
    const response = await fetch("/api/send-order", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        customerName: name,
        customerPhone: phone,
        customerEmail: email,
        customerAddress: address,
        productName: currentProduct.name,
        productPrice: currentProduct.price,
        color,
        storage,
        notes,
        cartItems: currentProduct.cartItems || null,
        isCart: currentProduct.isCart || false,
        orderDate: new Date().toLocaleString("fr-FR"),
      }),
    });

    const result = await response.json();

    if (result.success) {
      btn.innerHTML = `<i class="fas fa-check"></i> Email envoyé !`;
      btn.style.background = "#22c55e";
      setTimeout(() => {
        closeOrderModal({ target: null, currentTarget: { classList: { contains: () => true } } });
        showConfirmModal(name, currentProduct.name, currentProduct.price, color, storage, address, "Email ✅");
        btn.innerHTML = originalHTML;
        btn.style.background = "";
        btn.disabled = false;
      }, 1200);
    } else {
      throw new Error(result.error || "Erreur inconnue");
    }
  } catch (error) {
    console.error("Erreur envoi email:", error);
    btn.innerHTML = `<i class="fas fa-exclamation-triangle"></i> Erreur — Réessayez`;
    btn.style.background = "#e8001d";
    btn.disabled = false;
    setTimeout(() => {
      btn.innerHTML = originalHTML;
      btn.style.background = "";
    }, 3000);
  }
});

function shakeForm() {
  const form = document.getElementById("orderForm");
  form.style.animation = "none";
  form.offsetHeight;
  form.style.animation = "shake 0.5s ease";
  const style = document.createElement("style");
  style.textContent = `@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-8px)}75%{transform:translateX(8px)}}`;
  document.head.appendChild(style);

  // Highlight empty fields
  ["o-name", "o-phone", "o-email", "o-address"].forEach(id => {
    const el = document.getElementById(id);
    if (!el.value.trim()) {
      el.style.borderColor = "var(--red)";
      el.style.boxShadow = "0 0 0 3px rgba(232,0,29,0.2)";
      el.addEventListener("input", () => {
        el.style.borderColor = "";
        el.style.boxShadow = "";
      }, { once: true });
    }
  });
}

// ===== CONFIRMATION MODAL =====
function showConfirmModal(customerName, productName, productPrice, color, storage, address, method) {
  document.getElementById("confirmCustomerName").textContent = customerName.split(" ")[0];
  document.getElementById("confirmDetails").innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <span>📱 <strong>Produit</strong></span><span>${productName}</span>
      <span>💰 <strong>Prix</strong></span><span style="color:var(--red);font-weight:700">${productPrice}</span>
      <span>🎨 <strong>Couleur</strong></span><span>${color}</span>
      <span>💾 <strong>Stockage</strong></span><span>${storage}</span>
      <span>📍 <strong>Adresse</strong></span><span>${address}</span>
      <span>📤 <strong>Envoyé via</strong></span><span style="color:#25d366;font-weight:700">${method}</span>
    </div>
  `;

  document.getElementById("confirmOverlay").classList.add("open");
  document.body.style.overflow = "hidden";
  spawnConfetti();

  // Clear form
  ["o-name", "o-phone", "o-email", "o-address", "o-notes"].forEach(id => {
    document.getElementById(id).value = "";
  });
}

function closeConfirmModal() {
  document.getElementById("confirmOverlay").classList.remove("open");
  document.body.style.overflow = "";
}

function spawnConfetti() {
  const container = document.getElementById("confettiContainer");
  container.innerHTML = "";
  const colors = ["#e8001d", "#ff4560", "#ffffff", "#ffcc00", "#ff8800"];
  for (let i = 0; i < 50; i++) {
    const piece = document.createElement("div");
    piece.className = "confetti-piece";
    piece.style.cssText = `
      left: ${Math.random() * 100}%;
      top: ${-10 - Math.random() * 20}px;
      background: ${colors[Math.floor(Math.random() * colors.length)]};
      width: ${4 + Math.random() * 8}px;
      height: ${4 + Math.random() * 8}px;
      animation-duration: ${1 + Math.random() * 1.5}s;
      animation-delay: ${Math.random() * 0.8}s;
      border-radius: ${Math.random() > 0.5 ? "50%" : "2px"};
    `;
    container.appendChild(piece);
  }
}

// ===== CONTACT FORM =====
document.getElementById("contactForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const name = document.getElementById("cf-name").value.trim();
  const phone = document.getElementById("cf-phone").value.trim();
  const email = document.getElementById("cf-email").value.trim();
  const message = document.getElementById("cf-message").value.trim();

  if (!name || !phone || !email || !message) return;

  const waMsg = encodeURIComponent(
    `💬 *MESSAGE VIA LE SITE — ${CONFIG.storeName}*\n\n` +
    `👤 *Nom:* ${name}\n` +
    `📞 *Téléphone:* ${phone}\n` +
    `📧 *Email:* ${email}\n\n` +
    `📝 *Message:*\n${message}`
  );

  window.open(`https://wa.me/${CONFIG.whatsapp}?text=${waMsg}`, "_blank");

  const btn = e.target.querySelector(".btn-primary");
  btn.innerHTML = `<span>Message envoyé !</span> <i class="fas fa-check"></i>`;
  btn.style.background = "#25d366";
  setTimeout(() => {
    btn.innerHTML = `<span>Envoyer le message</span> <i class="fas fa-paper-plane"></i>`;
    btn.style.background = "";
    e.target.reset();
  }, 3000);
});

// ===== TESTIMONIALS SLIDER =====
function initTestimonials() {
  const track = document.getElementById("testimonialsTrack");
  const cards = track.querySelectorAll(".testimonial-card");
  const dotsContainer = document.getElementById("testiDots");

  cards.forEach((_, i) => {
    const dot = document.createElement("button");
    dot.className = "testi-dot" + (i === 0 ? " active" : "");
    dot.addEventListener("click", () => goToTestimonial(i));
    dotsContainer.appendChild(dot);
  });

  function goToTestimonial(index) {
    testimonialsIndex = index;
    const cardWidth = cards[0].offsetWidth + 24;
    track.style.transition = "transform 0.5s cubic-bezier(0.4,0,0.2,1)";
    track.style.transform = `translateX(-${index * cardWidth}px)`;
    document.querySelectorAll(".testi-dot").forEach((d, i) => {
      d.classList.toggle("active", i === index);
    });
  }

  // Auto-play
  setInterval(() => {
    const next = (testimonialsIndex + 1) % cards.length;
    goToTestimonial(next);
  }, 4000);

  // Touch/drag support
  let startX = 0, dragging = false;
  track.addEventListener("mousedown", (e) => { startX = e.clientX; dragging = true; });
  track.addEventListener("touchstart", (e) => { startX = e.touches[0].clientX; dragging = true; });
  track.addEventListener("mouseup", (e) => {
    if (!dragging) return; dragging = false;
    const diff = startX - e.clientX;
    if (Math.abs(diff) > 50) {
      const cards2 = track.querySelectorAll(".testimonial-card");
      if (diff > 0 && testimonialsIndex < cards2.length - 1) goToTestimonial(testimonialsIndex + 1);
      if (diff < 0 && testimonialsIndex > 0) goToTestimonial(testimonialsIndex - 1);
    }
  });
  track.addEventListener("touchend", (e) => {
    if (!dragging) return; dragging = false;
    const diff = startX - e.changedTouches[0].clientX;
    if (Math.abs(diff) > 50) {
      const cards2 = track.querySelectorAll(".testimonial-card");
      if (diff > 0 && testimonialsIndex < cards2.length - 1) goToTestimonial(testimonialsIndex + 1);
      if (diff < 0 && testimonialsIndex > 0) goToTestimonial(testimonialsIndex - 1);
    }
  });
}
initTestimonials();

// ===== PARALLAX ON HERO =====
window.addEventListener("scroll", () => {
  const scrolled = window.scrollY;
  const glow1 = document.querySelector(".glow-1");
  const glow2 = document.querySelector(".glow-2");
  if (glow1) glow1.style.transform = `translateY(${scrolled * 0.15}px)`;
  if (glow2) glow2.style.transform = `translateY(${-scrolled * 0.1}px)`;
});

// ===== STATS COUNTER ANIMATION =====
function animateCounters() {
  const stats = document.querySelectorAll(".stat strong");
  stats.forEach(stat => {
    const target = stat.textContent;
    const num = parseFloat(target.replace(/[^0-9.]/g, ""));
    const suffix = target.replace(/[0-9.]/g, "");
    if (isNaN(num)) return;
    let current = 0;
    const increment = num / 40;
    const timer = setInterval(() => {
      current += increment;
      if (current >= num) { current = num; clearInterval(timer); }
      stat.textContent = (Number.isInteger(num) ? Math.floor(current) : current.toFixed(0)) + suffix;
    }, 30);
  });
}

const heroSection = document.getElementById("hero");
const statsObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) { animateCounters(); statsObserver.unobserve(entry.target); }
  });
}, { threshold: 0.5 });
if (heroSection) statsObserver.observe(heroSection);

// ===== SMOOTH ANCHOR SCROLL =====
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener("click", (e) => {
    const target = document.querySelector(anchor.getAttribute("href"));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
});

// ===== FOOTER PRODUCT LINKS =====
function filterProducts(filter) {
  document.getElementById("products").scrollIntoView({ behavior: "smooth" });
  setTimeout(() => {
    const cards = document.querySelectorAll(".product-card");
    const btns = document.querySelectorAll(".filter-btn");
    btns.forEach(btn => btn.classList.toggle("active", btn.dataset.filter === filter));
    cards.forEach(card => {
      card.classList.toggle("hidden", filter !== "all" && card.dataset.serie !== filter);
    });
  }, 600);
}

// ===== PAGE TITLE EFFECT =====
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    document.title = "🍎 Revenez nous voir ! — GGS APPLE STORE";
  } else {
    document.title = "GGS APPLE STORE – iPhone Premium";
  }
});

// ===== LOG READY =====
console.log(
  "%c GEO APPLE STORE ",
  "background:#e8001d;color:white;font-size:16px;font-weight:bold;padding:8px 16px;border-radius:8px;",
  "\n🍎 Site chargé avec succès\n📱 WhatsApp: +22943924728\n📧 Email: michaelhologan45@gmail.com"
);