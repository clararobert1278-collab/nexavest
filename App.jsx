import { useState, useEffect, useCallback, createContext, useContext } from "react";

// ══════════════════════════════════════════════════════════════════════════════
// 🔐 SECURITY SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

// ── Password hashing (SHA-256 via Web Crypto API) ──
const hashPassword = async (password) => {
  const msgBuffer = new TextEncoder().encode(password + "nexavest_salt_2024");
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
};

// ── Input sanitizer — strips HTML/script tags ──
const sanitize = (str = "") => String(str)
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#x27;")
  .replace(/\//g, "&#x2F;")
  .trim()
  .slice(0, 500);

// ── Password strength checker ──
const checkPasswordStrength = (pwd) => {
  const checks = {
    length:    pwd.length >= 8,
    uppercase: /[A-Z]/.test(pwd),
    lowercase: /[a-z]/.test(pwd),
    number:    /[0-9]/.test(pwd),
    special:   /[^A-Za-z0-9]/.test(pwd),
  };
  const score = Object.values(checks).filter(Boolean).length;
  const label = score <= 1 ? "Very Weak" : score === 2 ? "Weak" : score === 3 ? "Fair" : score === 4 ? "Strong" : "Very Strong";
  const color = score <= 1 ? "#EF4444" : score === 2 ? "#F97316" : score === 3 ? "#F5C842" : score === 4 ? "#4ADE80" : "#22D3EE";
  return { score, label, color, checks };
};

// ── Brute-force / rate limiter ──
const RATE_LIMIT_KEY = "nexavest_ratelimit";
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

const rateLimiter = {
  get: (email) => {
    try {
      const raw = localStorage.getItem(RATE_LIMIT_KEY);
      const data = raw ? JSON.parse(raw) : {};
      return data[email] || { attempts: 0, lockedUntil: null };
    } catch { return { attempts: 0, lockedUntil: null }; }
  },
  increment: (email) => {
    try {
      const raw = localStorage.getItem(RATE_LIMIT_KEY);
      const data = raw ? JSON.parse(raw) : {};
      const current = data[email] || { attempts: 0, lockedUntil: null };
      current.attempts += 1;
      if (current.attempts >= MAX_ATTEMPTS) {
        current.lockedUntil = Date.now() + LOCKOUT_MS;
      }
      data[email] = current;
      localStorage.setItem(RATE_LIMIT_KEY, JSON.stringify(data));
      return current;
    } catch { return { attempts: 0, lockedUntil: null }; }
  },
  reset: (email) => {
    try {
      const raw = localStorage.getItem(RATE_LIMIT_KEY);
      const data = raw ? JSON.parse(raw) : {};
      delete data[email];
      localStorage.setItem(RATE_LIMIT_KEY, JSON.stringify(data));
    } catch {}
  },
  isLocked: (email) => {
    const r = rateLimiter.get(email);
    if (r.lockedUntil && Date.now() < r.lockedUntil) return r.lockedUntil;
    if (r.lockedUntil && Date.now() >= r.lockedUntil) rateLimiter.reset(email);
    return false;
  },
};

// ── Session manager — expires after 24 hours ──
const SESSION_KEY = "nexavest_session";
const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

const sessionManager = {
  save: (user) => {
    const session = { user, expiresAt: Date.now() + SESSION_EXPIRY_MS };
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  },
  get: () => {
    try {
      const raw = localStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const { user, expiresAt } = JSON.parse(raw);
      if (Date.now() > expiresAt) {
        localStorage.removeItem(SESSION_KEY);
        return null;
      }
      return user;
    } catch { return null; }
  },
  clear: () => localStorage.removeItem(SESSION_KEY),
  refresh: (user) => sessionManager.save(user),
};

// ── Security audit log ──
const securityLog = {
  log: (event, details = {}) => {
    try {
      const d = db.get();
      if (!d.securityLog) d.securityLog = [];
      d.securityLog.push({
        id: Math.random().toString(36).slice(2),
        event,
        details,
        ip: "client-side",
        userAgent: navigator.userAgent.slice(0, 80),
        timestamp: new Date().toISOString(),
      });
      // Keep only last 200 entries
      if (d.securityLog.length > 200) d.securityLog = d.securityLog.slice(-200);
      db.save(d);
    } catch {}
  },
};

// ── Email validator ──
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ── CSRF token generator (for form submissions) ──
const generateCSRFToken = () => {
  const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
  sessionStorage.setItem("csrf_token", token);
  return token;
};

// ── Password Strength Meter Component ──
function PasswordStrengthMeter({ password }) {
  if (!password) return null;
  const { score, label, color, checks } = checkPasswordStrength(password);
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ display: "flex", gap: 4, marginBottom: 6 }}>
        {[1,2,3,4,5].map(i => (
          <div key={i} style={{ flex: 1, height: 4, borderRadius: 2, background: i <= score ? color : "#1C2538", transition: "background 0.3s" }} />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
        <span style={{ color, fontWeight: 700 }}>{label}</span>
        <div style={{ display: "flex", gap: 8, color: "#9DAED0" }}>
          {[["8+ chars", checks.length], ["A-Z", checks.uppercase], ["0-9", checks.number], ["#@!", checks.special]].map(([l, ok]) => (
            <span key={l} style={{ color: ok ? "#4ADE80" : "#9DAED0" }}>{ok ? "✓" : "○"} {l}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Security Badge Component ──
function SecurityBadges() {
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center", margin: "16px 0" }}>
      {[
        { icon: "🔒", label: "256-bit Encrypted" },
        { icon: "🛡️", label: "Brute-Force Protected" },
        { icon: "⏱️", label: "Auto Session Expiry" },
        { icon: "🔍", label: "Activity Monitored" },
      ].map(b => (
        <div key={b.label} style={{ display: "flex", alignItems: "center", gap: 5, background: "rgba(74,222,128,0.08)", border: "1px solid rgba(74,222,128,0.2)", borderRadius: 20, padding: "4px 10px", fontSize: 11, color: "#4ADE80", fontWeight: 600 }}>
          {b.icon} {b.label}
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// LANGUAGE / i18n SYSTEM
// ══════════════════════════════════════════════════════════════════════════════
const LANGUAGES = [
  { code: "en", name: "English",    flag: "🇬🇧", dir: "ltr" },
  { code: "es", name: "Español",    flag: "🇪🇸", dir: "ltr" },
  { code: "fr", name: "Français",   flag: "🇫🇷", dir: "ltr" },
  { code: "ar", name: "العربية",    flag: "🇸🇦", dir: "rtl" },
  { code: "zh", name: "中文",        flag: "🇨🇳", dir: "ltr" },
  { code: "pt", name: "Português",  flag: "🇧🇷", dir: "ltr" },
  { code: "hi", name: "हिन्दी",      flag: "🇮🇳", dir: "ltr" },
  { code: "ru", name: "Русский",    flag: "🇷🇺", dir: "ltr" },
  { code: "id", name: "Indonesia",  flag: "🇮🇩", dir: "ltr" },
  { code: "tr", name: "Türkçe",     flag: "🇹🇷", dir: "ltr" },
];

const TRANSLATIONS = {
  en: {
    // Nav
    plans: "Plans", howItWorks: "How It Works", referrals: "Referrals", about: "About",
    signIn: "Sign In", getStarted: "Get Started",
    // Hero
    heroTitle: "Grow Your Wealth Across Every Border",
    heroSub: "Join investors from 150+ countries earning consistent returns with our professionally managed investment portfolios.",
    startInvesting: "Start Investing Today", viewPlans: "View Plans",
    totalManaged: "Total Managed", activeInvestors: "Active Investors",
    payoutRate: "Payout Rate", countries: "Countries",
    // Plans
    investmentPlans: "Investment Plans", chooseGrowthPath: "Choose Your Growth Path",
    plansDesc: "Select the plan that matches your investment goals. All plans include daily profit tracking and 24/7 support.",
    roiLabel: "ROI", overDays: "Over {n} days", minLabel: "Min", maxLabel: "Max",
    dailyUpdates: "Daily profit updates", support247: "24/7 support",
    instantWithdrawal: "Instant withdrawal", investNow: "Invest Now →",
    // How it works
    howItWorksTitle: "How It Works", threeSteps: "Start earning in three simple steps",
    step1Title: "Create Account", step1Desc: "Sign up in under 2 minutes with just your email.",
    step2Title: "Deposit Funds", step2Desc: "Fund your account via Bitcoin, Ethereum, USDT, bank transfer, or e-wallet.",
    step3Title: "Earn Returns", step3Desc: "Your money works 24/7. Track earnings in real-time and withdraw anytime.",
    // Referral landing
    referralProgram: "Referral Program", earnWhileShare: "Earn While You Share",
    referralDesc: "Invite friends and earn on 3 levels — your referrals, their referrals, and theirs too.",
    directReferrals: "Direct referrals", theirReferrals: "Their referrals", thirdGen: "3rd generation",
    getReferralLink: "Get My Referral Link →",
    // Auth
    welcomeBack: "Welcome back", signInAccount: "Sign in to your investment account",
    createAccount: "Create Account", join14k: "Join 14,000+ global investors",
    fullName: "Full Name", emailAddress: "Email Address", country: "Country",
    password: "Password", confirmPassword: "Confirm Password",
    referralCode: "Referral Code (optional)", alreadyHave: "Already have an account?",
    dontHave: "Don't have an account?", signUp: "Sign up",
    // Dashboard tabs
    overview: "Overview", invest: "Invest", deposit: "Deposit",
    withdraw: "Withdraw", history: "History", support: "Support", notifications: "Notifications",
    // Overview
    availableBalance: "Available Balance", totalInvested: "Total Invested",
    totalEarned: "Total Earned", referralEarnings: "Referral Earnings",
    activeInvestment: "Active Investment", quickActions: "Quick Actions",
    recentTransactions: "Recent Transactions", viewAll: "View All",
    // Invest
    selectPlan: "Select a Plan", configureInvestment: "Configure Investment",
    investmentAmount: "Investment Amount (USD)", expectedProfit: "Expected Profit",
    totalReturn: "Total Return", confirmInvestment: "Confirm Investment →",
    // Deposit
    depositFunds: "Deposit Funds", selectPaymentMethod: "Select Payment Method",
    cryptocurrency: "Cryptocurrency", bankTransfer: "Bank Transfer", eWallets: "E-Wallets",
    walletAddress: "Wallet Address", paymentDetails: "Payment Details",
    afterSending: "After sending, submit your transaction ID via support. Credited within 30–60 minutes.",
    iSent: "I've Sent Payment →",
    // Withdraw
    withdrawFunds: "Withdraw Funds", availableBalance2: "Available Balance",
    selectAccount: "Select Withdrawal Account", enterAmount: "Enter Amount",
    processingFee: "Processing fee (1.5%)", youReceive: "You receive",
    confirmWithdrawal: "Confirm Withdrawal", submitWithdrawal: "Submit Withdrawal Request",
    myAccounts: "My Accounts", addAccount: "Add Account",
    accountLabel: "Account Label", accountType: "Account Type",
    bankName: "Bank Name", accountHolderName: "Account Holder Name",
    accountNumber: "Account Number", routingNumber: "Routing Number",
    swiftCode: "SWIFT / BIC Code", ibanLabel: "IBAN",
    saveAccount: "Save Account", noAccountsYet: "No Accounts Added Yet",
    // Support
    hereToHelp: "We're Here to Help", fastResponse: "Fast Response",
    available247: "24/7 Available", securePrivate: "Secure & Private",
    faqTitle: "Frequently Asked Questions", sendMessage: "Send a Message",
    yourName: "Your Name", subject: "Subject", message: "Message",
    sendBtn: "Send Message →", messageSent: "Message sent! We'll get back to you within 24 hours.",
    // Notifications
    notificationsTitle: "Notifications", allCaughtUp: "All caught up!",
    unread: "unread", total: "total", markAllRead: "Mark all as read",
    noNotifications: "No Notifications", markRead: "Mark read",
    // Footer
    globalPlatform: "Global Investment Platform — Serving investors in 150+ countries",
    riskWarning: "Investment involves risk. Past performance does not guarantee future results.",
  },

  es: {
    plans: "Planes", howItWorks: "Cómo Funciona", referrals: "Referidos", about: "Acerca de",
    signIn: "Iniciar Sesión", getStarted: "Comenzar",
    heroTitle: "Haz Crecer Tu Patrimonio Sin Fronteras",
    heroSub: "Únete a inversores de más de 150 países que obtienen rendimientos consistentes con nuestras carteras gestionadas profesionalmente.",
    startInvesting: "Comenzar a Invertir Hoy", viewPlans: "Ver Planes",
    totalManaged: "Total Gestionado", activeInvestors: "Inversores Activos",
    payoutRate: "Tasa de Pago", countries: "Países",
    investmentPlans: "Planes de Inversión", chooseGrowthPath: "Elige Tu Ruta de Crecimiento",
    plansDesc: "Selecciona el plan que se adapte a tus objetivos. Todos incluyen seguimiento diario y soporte 24/7.",
    roiLabel: "ROI", overDays: "En {n} días", minLabel: "Mín", maxLabel: "Máx",
    dailyUpdates: "Actualizaciones diarias de ganancias", support247: "Soporte 24/7",
    instantWithdrawal: "Retiro instantáneo", investNow: "Invertir Ahora →",
    howItWorksTitle: "Cómo Funciona", threeSteps: "Comienza a ganar en tres simples pasos",
    step1Title: "Crear Cuenta", step1Desc: "Regístrate en menos de 2 minutos solo con tu correo.",
    step2Title: "Depositar Fondos", step2Desc: "Financia tu cuenta con Bitcoin, Ethereum, USDT, transferencia bancaria o billetera electrónica.",
    step3Title: "Ganar Rendimientos", step3Desc: "Tu dinero trabaja 24/7. Sigue tus ganancias en tiempo real y retira cuando quieras.",
    referralProgram: "Programa de Referidos", earnWhileShare: "Gana Mientras Compartes",
    referralDesc: "Invita amigos y gana en 3 niveles — tus referidos, los referidos de ellos y los suyos también.",
    directReferrals: "Referidos directos", theirReferrals: "Sus referidos", thirdGen: "3ra generación",
    getReferralLink: "Obtener Mi Enlace de Referido →",
    welcomeBack: "Bienvenido de vuelta", signInAccount: "Inicia sesión en tu cuenta de inversión",
    createAccount: "Crear Cuenta", join14k: "Únete a más de 14.000 inversores globales",
    fullName: "Nombre Completo", emailAddress: "Correo Electrónico", country: "País",
    password: "Contraseña", confirmPassword: "Confirmar Contraseña",
    referralCode: "Código de Referido (opcional)", alreadyHave: "¿Ya tienes una cuenta?",
    dontHave: "¿No tienes una cuenta?", signUp: "Regístrate",
    overview: "Resumen", invest: "Invertir", deposit: "Depósito",
    withdraw: "Retiro", history: "Historial", support: "Soporte", notifications: "Notificaciones",
    availableBalance: "Saldo Disponible", totalInvested: "Total Invertido",
    totalEarned: "Total Ganado", referralEarnings: "Ganancias por Referidos",
    activeInvestment: "Inversión Activa", quickActions: "Acciones Rápidas",
    recentTransactions: "Transacciones Recientes", viewAll: "Ver Todo",
    selectPlan: "Seleccionar Plan", configureInvestment: "Configurar Inversión",
    investmentAmount: "Monto de Inversión (USD)", expectedProfit: "Ganancia Esperada",
    totalReturn: "Retorno Total", confirmInvestment: "Confirmar Inversión →",
    depositFunds: "Depositar Fondos", selectPaymentMethod: "Seleccionar Método de Pago",
    cryptocurrency: "Criptomoneda", bankTransfer: "Transferencia Bancaria", eWallets: "Billeteras Electrónicas",
    walletAddress: "Dirección de Billetera", paymentDetails: "Detalles de Pago",
    afterSending: "Después de enviar, comparte tu ID de transacción por soporte. Acreditado en 30–60 minutos.",
    iSent: "He Enviado el Pago →",
    withdrawFunds: "Retirar Fondos", availableBalance2: "Saldo Disponible",
    selectAccount: "Seleccionar Cuenta de Retiro", enterAmount: "Ingresar Monto",
    processingFee: "Tarifa de procesamiento (1.5%)", youReceive: "Recibes",
    confirmWithdrawal: "Confirmar Retiro", submitWithdrawal: "Enviar Solicitud de Retiro",
    myAccounts: "Mis Cuentas", addAccount: "Agregar Cuenta",
    accountLabel: "Etiqueta de Cuenta", accountType: "Tipo de Cuenta",
    bankName: "Nombre del Banco", accountHolderName: "Nombre del Titular",
    accountNumber: "Número de Cuenta", routingNumber: "Número de Enrutamiento",
    swiftCode: "Código SWIFT / BIC", ibanLabel: "IBAN",
    saveAccount: "Guardar Cuenta", noAccountsYet: "Aún No Hay Cuentas",
    hereToHelp: "Estamos Aquí para Ayudar", fastResponse: "Respuesta Rápida",
    available247: "Disponible 24/7", securePrivate: "Seguro y Privado",
    faqTitle: "Preguntas Frecuentes", sendMessage: "Enviar Mensaje",
    yourName: "Tu Nombre", subject: "Asunto", message: "Mensaje",
    sendBtn: "Enviar Mensaje →", messageSent: "¡Mensaje enviado! Te responderemos en 24 horas.",
    notificationsTitle: "Notificaciones", allCaughtUp: "¡Todo al día!",
    unread: "sin leer", total: "total", markAllRead: "Marcar todo como leído",
    noNotifications: "Sin Notificaciones", markRead: "Marcar como leído",
    globalPlatform: "Plataforma de Inversión Global — Sirviendo a inversores en más de 150 países",
    riskWarning: "Invertir conlleva riesgos. El rendimiento pasado no garantiza resultados futuros.",
  },

  fr: {
    plans: "Plans", howItWorks: "Comment ça Marche", referrals: "Parrainages", about: "À Propos",
    signIn: "Se Connecter", getStarted: "Commencer",
    heroTitle: "Faites Fructifier Votre Patrimoine Sans Frontières",
    heroSub: "Rejoignez des investisseurs de plus de 150 pays qui obtiennent des rendements réguliers.",
    startInvesting: "Commencer à Investir", viewPlans: "Voir les Plans",
    totalManaged: "Total Géré", activeInvestors: "Investisseurs Actifs",
    payoutRate: "Taux de Paiement", countries: "Pays",
    investmentPlans: "Plans d'Investissement", chooseGrowthPath: "Choisissez Votre Voie",
    plansDesc: "Sélectionnez le plan qui correspond à vos objectifs. Tous incluent un suivi quotidien et un support 24/7.",
    roiLabel: "ROI", overDays: "Sur {n} jours", minLabel: "Min", maxLabel: "Max",
    dailyUpdates: "Mises à jour quotidiennes", support247: "Support 24/7",
    instantWithdrawal: "Retrait instantané", investNow: "Investir Maintenant →",
    howItWorksTitle: "Comment ça Marche", threeSteps: "Commencez en trois étapes simples",
    step1Title: "Créer un Compte", step1Desc: "Inscrivez-vous en moins de 2 minutes avec votre e-mail.",
    step2Title: "Déposer des Fonds", step2Desc: "Financez via Bitcoin, Ethereum, USDT, virement bancaire ou e-wallet.",
    step3Title: "Gagner des Rendements", step3Desc: "Votre argent travaille 24/7. Suivez vos gains en temps réel.",
    referralProgram: "Programme de Parrainage", earnWhileShare: "Gagnez en Partageant",
    referralDesc: "Invitez des amis et gagnez sur 3 niveaux — vos filleuls, leurs filleuls et au-delà.",
    directReferrals: "Filleuls directs", theirReferrals: "Leurs filleuls", thirdGen: "3e génération",
    getReferralLink: "Obtenir Mon Lien de Parrainage →",
    welcomeBack: "Bon retour", signInAccount: "Connectez-vous à votre compte d'investissement",
    createAccount: "Créer un Compte", join14k: "Rejoignez plus de 14 000 investisseurs",
    fullName: "Nom Complet", emailAddress: "Adresse E-mail", country: "Pays",
    password: "Mot de Passe", confirmPassword: "Confirmer le Mot de Passe",
    referralCode: "Code de Parrainage (facultatif)", alreadyHave: "Vous avez déjà un compte?",
    dontHave: "Pas encore de compte?", signUp: "S'inscrire",
    overview: "Aperçu", invest: "Investir", deposit: "Dépôt",
    withdraw: "Retrait", history: "Historique", support: "Support", notifications: "Notifications",
    availableBalance: "Solde Disponible", totalInvested: "Total Investi",
    totalEarned: "Total Gagné", referralEarnings: "Gains de Parrainage",
    activeInvestment: "Investissement Actif", quickActions: "Actions Rapides",
    recentTransactions: "Transactions Récentes", viewAll: "Voir Tout",
    selectPlan: "Choisir un Plan", configureInvestment: "Configurer l'Investissement",
    investmentAmount: "Montant d'Investissement (USD)", expectedProfit: "Bénéfice Attendu",
    totalReturn: "Retour Total", confirmInvestment: "Confirmer l'Investissement →",
    depositFunds: "Déposer des Fonds", selectPaymentMethod: "Sélectionner la Méthode de Paiement",
    cryptocurrency: "Cryptomonnaie", bankTransfer: "Virement Bancaire", eWallets: "Portefeuilles Électroniques",
    walletAddress: "Adresse du Portefeuille", paymentDetails: "Détails de Paiement",
    afterSending: "Après envoi, soumettez votre ID de transaction via le support. Crédité en 30–60 minutes.",
    iSent: "J'ai Envoyé le Paiement →",
    withdrawFunds: "Retirer des Fonds", availableBalance2: "Solde Disponible",
    selectAccount: "Sélectionner un Compte", enterAmount: "Entrer le Montant",
    processingFee: "Frais de traitement (1.5%)", youReceive: "Vous recevez",
    confirmWithdrawal: "Confirmer le Retrait", submitWithdrawal: "Soumettre la Demande de Retrait",
    myAccounts: "Mes Comptes", addAccount: "Ajouter un Compte",
    accountLabel: "Libellé du Compte", accountType: "Type de Compte",
    bankName: "Nom de la Banque", accountHolderName: "Nom du Titulaire",
    accountNumber: "Numéro de Compte", routingNumber: "Numéro de Routage",
    swiftCode: "Code SWIFT / BIC", ibanLabel: "IBAN",
    saveAccount: "Enregistrer le Compte", noAccountsYet: "Aucun Compte Ajouté",
    hereToHelp: "Nous Sommes Là pour Vous Aider", fastResponse: "Réponse Rapide",
    available247: "Disponible 24/7", securePrivate: "Sécurisé et Privé",
    faqTitle: "Questions Fréquentes", sendMessage: "Envoyer un Message",
    yourName: "Votre Nom", subject: "Sujet", message: "Message",
    sendBtn: "Envoyer →", messageSent: "Message envoyé! Nous vous répondrons dans les 24 heures.",
    notificationsTitle: "Notifications", allCaughtUp: "Tout est à jour!",
    unread: "non lu", total: "total", markAllRead: "Tout marquer comme lu",
    noNotifications: "Pas de Notifications", markRead: "Marquer comme lu",
    globalPlatform: "Plateforme d'Investissement Mondiale — Au service des investisseurs dans plus de 150 pays",
    riskWarning: "Investir comporte des risques. Les performances passées ne garantissent pas les résultats futurs.",
  },

  ar: {
    plans: "الخطط", howItWorks: "كيف يعمل", referrals: "الإحالات", about: "حول",
    signIn: "تسجيل الدخول", getStarted: "ابدأ الآن",
    heroTitle: "نمِّ ثروتك عبر كل الحدود",
    heroSub: "انضم إلى مستثمرين من أكثر من 150 دولة يحققون عوائد ثابتة مع محافظنا المُدارة باحترافية.",
    startInvesting: "ابدأ الاستثمار اليوم", viewPlans: "عرض الخطط",
    totalManaged: "إجمالي المُدار", activeInvestors: "المستثمرون النشطون",
    payoutRate: "معدل الدفع", countries: "دولة",
    investmentPlans: "خطط الاستثمار", chooseGrowthPath: "اختر مسار نموك",
    plansDesc: "اختر الخطة التي تناسب أهدافك الاستثمارية. تتضمن جميع الخطط تتبعاً يومياً للأرباح ودعماً على مدار الساعة.",
    roiLabel: "عائد", overDays: "على مدى {n} يوماً", minLabel: "الحد الأدنى", maxLabel: "الحد الأقصى",
    dailyUpdates: "تحديثات يومية للأرباح", support247: "دعم على مدار الساعة",
    instantWithdrawal: "سحب فوري", investNow: "استثمر الآن →",
    howItWorksTitle: "كيف يعمل", threeSteps: "ابدأ في كسب الأرباح في ثلاث خطوات بسيطة",
    step1Title: "إنشاء حساب", step1Desc: "سجّل في أقل من دقيقتين ببريدك الإلكتروني فقط.",
    step2Title: "إيداع الأموال", step2Desc: "موّل حسابك عبر بيتكوين أو إيثريوم أو USDT أو تحويل بنكي أو محفظة إلكترونية.",
    step3Title: "كسب العوائد", step3Desc: "أموالك تعمل 24/7. تتبع أرباحك في الوقت الفعلي واسحب في أي وقت.",
    referralProgram: "برنامج الإحالة", earnWhileShare: "اكسب بينما تشارك",
    referralDesc: "ادعُ أصدقاءك واكسب على 3 مستويات — إحالاتك وإحالاتهم وما هو أبعد.",
    directReferrals: "الإحالات المباشرة", theirReferrals: "إحالاتهم", thirdGen: "الجيل الثالث",
    getReferralLink: "احصل على رابط الإحالة الخاص بي →",
    welcomeBack: "مرحباً بعودتك", signInAccount: "سجّل الدخول إلى حساب الاستثمار الخاص بك",
    createAccount: "إنشاء حساب", join14k: "انضم إلى أكثر من 14,000 مستثمر عالمي",
    fullName: "الاسم الكامل", emailAddress: "البريد الإلكتروني", country: "البلد",
    password: "كلمة المرور", confirmPassword: "تأكيد كلمة المرور",
    referralCode: "رمز الإحالة (اختياري)", alreadyHave: "هل لديك حساب بالفعل؟",
    dontHave: "ليس لديك حساب؟", signUp: "سجّل",
    overview: "نظرة عامة", invest: "استثمر", deposit: "إيداع",
    withdraw: "سحب", history: "السجل", support: "الدعم", notifications: "الإشعارات",
    availableBalance: "الرصيد المتاح", totalInvested: "إجمالي الاستثمار",
    totalEarned: "إجمالي الأرباح", referralEarnings: "أرباح الإحالة",
    activeInvestment: "الاستثمار النشط", quickActions: "الإجراءات السريعة",
    recentTransactions: "المعاملات الأخيرة", viewAll: "عرض الكل",
    selectPlan: "اختر خطة", configureInvestment: "تهيئة الاستثمار",
    investmentAmount: "مبلغ الاستثمار (USD)", expectedProfit: "الربح المتوقع",
    totalReturn: "العائد الإجمالي", confirmInvestment: "تأكيد الاستثمار →",
    depositFunds: "إيداع الأموال", selectPaymentMethod: "اختر طريقة الدفع",
    cryptocurrency: "العملات المشفرة", bankTransfer: "تحويل بنكي", eWallets: "المحافظ الإلكترونية",
    walletAddress: "عنوان المحفظة", paymentDetails: "تفاصيل الدفع",
    afterSending: "بعد الإرسال، قدّم معرّف معاملتك عبر الدعم. يُضاف في 30-60 دقيقة.",
    iSent: "لقد أرسلت الدفعة →",
    withdrawFunds: "سحب الأموال", availableBalance2: "الرصيد المتاح",
    selectAccount: "اختر حساب السحب", enterAmount: "أدخل المبلغ",
    processingFee: "رسوم المعالجة (1.5%)", youReceive: "ستتلقى",
    confirmWithdrawal: "تأكيد السحب", submitWithdrawal: "إرسال طلب السحب",
    myAccounts: "حساباتي", addAccount: "إضافة حساب",
    accountLabel: "تسمية الحساب", accountType: "نوع الحساب",
    bankName: "اسم البنك", accountHolderName: "اسم صاحب الحساب",
    accountNumber: "رقم الحساب", routingNumber: "رقم التوجيه",
    swiftCode: "رمز SWIFT / BIC", ibanLabel: "IBAN",
    saveAccount: "حفظ الحساب", noAccountsYet: "لا توجد حسابات بعد",
    hereToHelp: "نحن هنا للمساعدة", fastResponse: "استجابة سريعة",
    available247: "متاح 24/7", securePrivate: "آمن وخاص",
    faqTitle: "الأسئلة الشائعة", sendMessage: "إرسال رسالة",
    yourName: "اسمك", subject: "الموضوع", message: "الرسالة",
    sendBtn: "إرسال →", messageSent: "تم إرسال الرسالة! سنعود إليك خلال 24 ساعة.",
    notificationsTitle: "الإشعارات", allCaughtUp: "كل شيء على ما يرام!",
    unread: "غير مقروء", total: "إجمالي", markAllRead: "وضع علامة مقروء على الكل",
    noNotifications: "لا توجد إشعارات", markRead: "وضع علامة مقروء",
    globalPlatform: "منصة استثمار عالمية — تخدم المستثمرين في أكثر من 150 دولة",
    riskWarning: "الاستثمار ينطوي على مخاطر. الأداء السابق لا يضمن النتائج المستقبلية.",
  },

  zh: {
    plans: "方案", howItWorks: "运作方式", referrals: "推荐", about: "关于",
    signIn: "登录", getStarted: "开始",
    heroTitle: "跨越国界增值财富",
    heroSub: "加入来自150多个国家的投资者，通过我们专业管理的投资组合获得稳定回报。",
    startInvesting: "立即开始投资", viewPlans: "查看方案",
    totalManaged: "总管理资产", activeInvestors: "活跃投资者",
    payoutRate: "支付率", countries: "国家",
    investmentPlans: "投资方案", chooseGrowthPath: "选择您的增长路径",
    plansDesc: "选择符合您投资目标的方案。所有方案均包含每日利润跟踪和全天候支持。",
    roiLabel: "收益率", overDays: "{n}天内", minLabel: "最低", maxLabel: "最高",
    dailyUpdates: "每日利润更新", support247: "全天候支持",
    instantWithdrawal: "即时提款", investNow: "立即投资 →",
    howItWorksTitle: "运作方式", threeSteps: "三个简单步骤开始赚取收益",
    step1Title: "创建账户", step1Desc: "只需邮箱，2分钟内完成注册。",
    step2Title: "存入资金", step2Desc: "通过比特币、以太坊、USDT、银行转账或电子钱包为账户充值。",
    step3Title: "获得回报", step3Desc: "您的资金全天候运作。实时跟踪收益，随时提款。",
    referralProgram: "推荐计划", earnWhileShare: "分享即赚钱",
    referralDesc: "邀请朋友并在3个级别获得佣金——您的推荐人、他们的推荐人及更多。",
    directReferrals: "直接推荐", theirReferrals: "他们的推荐", thirdGen: "第三代",
    getReferralLink: "获取我的推荐链接 →",
    welcomeBack: "欢迎回来", signInAccount: "登录您的投资账户",
    createAccount: "创建账户", join14k: "加入14,000+全球投资者",
    fullName: "全名", emailAddress: "电子邮件", country: "国家",
    password: "密码", confirmPassword: "确认密码",
    referralCode: "推荐码（可选）", alreadyHave: "已有账户？",
    dontHave: "没有账户？", signUp: "注册",
    overview: "概览", invest: "投资", deposit: "存款",
    withdraw: "提款", history: "历史", support: "支持", notifications: "通知",
    availableBalance: "可用余额", totalInvested: "总投资",
    totalEarned: "总收益", referralEarnings: "推荐收益",
    activeInvestment: "活跃投资", quickActions: "快速操作",
    recentTransactions: "近期交易", viewAll: "查看全部",
    selectPlan: "选择方案", configureInvestment: "配置投资",
    investmentAmount: "投资金额（美元）", expectedProfit: "预期收益",
    totalReturn: "总回报", confirmInvestment: "确认投资 →",
    depositFunds: "存入资金", selectPaymentMethod: "选择付款方式",
    cryptocurrency: "加密货币", bankTransfer: "银行转账", eWallets: "电子钱包",
    walletAddress: "钱包地址", paymentDetails: "付款详情",
    afterSending: "发送后，请通过客服提交您的交易ID。30-60分钟内入账。",
    iSent: "我已发送付款 →",
    withdrawFunds: "提取资金", availableBalance2: "可用余额",
    selectAccount: "选择提款账户", enterAmount: "输入金额",
    processingFee: "处理费（1.5%）", youReceive: "您将收到",
    confirmWithdrawal: "确认提款", submitWithdrawal: "提交提款申请",
    myAccounts: "我的账户", addAccount: "添加账户",
    accountLabel: "账户标签", accountType: "账户类型",
    bankName: "银行名称", accountHolderName: "账户持有人姓名",
    accountNumber: "账号", routingNumber: "路由号码",
    swiftCode: "SWIFT / BIC代码", ibanLabel: "IBAN",
    saveAccount: "保存账户", noAccountsYet: "尚未添加账户",
    hereToHelp: "我们随时为您服务", fastResponse: "快速响应",
    available247: "全天候在线", securePrivate: "安全私密",
    faqTitle: "常见问题", sendMessage: "发送消息",
    yourName: "您的姓名", subject: "主题", message: "消息",
    sendBtn: "发送 →", messageSent: "消息已发送！我们将在24小时内回复您。",
    notificationsTitle: "通知", allCaughtUp: "全部已读！",
    unread: "未读", total: "总计", markAllRead: "全部标为已读",
    noNotifications: "暂无通知", markRead: "标为已读",
    globalPlatform: "全球投资平台——为150多个国家的投资者提供服务",
    riskWarning: "投资存在风险。过往业绩不代表未来收益。",
  },

  pt: {
    plans: "Planos", howItWorks: "Como Funciona", referrals: "Indicações", about: "Sobre",
    signIn: "Entrar", getStarted: "Começar",
    heroTitle: "Faça Seu Patrimônio Crescer Sem Fronteiras",
    heroSub: "Junte-se a investidores de mais de 150 países que obtêm retornos consistentes com nossos portfólios gerenciados profissionalmente.",
    startInvesting: "Comece a Investir Hoje", viewPlans: "Ver Planos",
    totalManaged: "Total Gerenciado", activeInvestors: "Investidores Ativos",
    payoutRate: "Taxa de Pagamento", countries: "Países",
    investmentPlans: "Planos de Investimento", chooseGrowthPath: "Escolha Seu Caminho",
    plansDesc: "Selecione o plano que combina com seus objetivos. Todos incluem acompanhamento diário e suporte 24/7.",
    roiLabel: "ROI", overDays: "Em {n} dias", minLabel: "Mín", maxLabel: "Máx",
    dailyUpdates: "Atualizações diárias de lucro", support247: "Suporte 24/7",
    instantWithdrawal: "Saque instantâneo", investNow: "Investir Agora →",
    howItWorksTitle: "Como Funciona", threeSteps: "Comece a ganhar em três etapas simples",
    step1Title: "Criar Conta", step1Desc: "Cadastre-se em menos de 2 minutos com seu e-mail.",
    step2Title: "Depositar Fundos", step2Desc: "Financie sua conta via Bitcoin, Ethereum, USDT, transferência bancária ou carteira digital.",
    step3Title: "Ganhar Retornos", step3Desc: "Seu dinheiro trabalha 24/7. Acompanhe seus ganhos em tempo real e saque quando quiser.",
    referralProgram: "Programa de Indicação", earnWhileShare: "Ganhe Enquanto Compartilha",
    referralDesc: "Convide amigos e ganhe em 3 níveis — seus indicados, os indicados deles e mais.",
    directReferrals: "Indicados diretos", theirReferrals: "Indicados deles", thirdGen: "3ª geração",
    getReferralLink: "Obter Meu Link de Indicação →",
    welcomeBack: "Bem-vindo de volta", signInAccount: "Entre na sua conta de investimento",
    createAccount: "Criar Conta", join14k: "Junte-se a mais de 14.000 investidores globais",
    fullName: "Nome Completo", emailAddress: "Endereço de E-mail", country: "País",
    password: "Senha", confirmPassword: "Confirmar Senha",
    referralCode: "Código de Indicação (opcional)", alreadyHave: "Já tem uma conta?",
    dontHave: "Não tem uma conta?", signUp: "Cadastre-se",
    overview: "Visão Geral", invest: "Investir", deposit: "Depósito",
    withdraw: "Saque", history: "Histórico", support: "Suporte", notifications: "Notificações",
    availableBalance: "Saldo Disponível", totalInvested: "Total Investido",
    totalEarned: "Total Ganho", referralEarnings: "Ganhos de Indicação",
    activeInvestment: "Investimento Ativo", quickActions: "Ações Rápidas",
    recentTransactions: "Transações Recentes", viewAll: "Ver Tudo",
    selectPlan: "Selecionar Plano", configureInvestment: "Configurar Investimento",
    investmentAmount: "Valor do Investimento (USD)", expectedProfit: "Lucro Esperado",
    totalReturn: "Retorno Total", confirmInvestment: "Confirmar Investimento →",
    depositFunds: "Depositar Fundos", selectPaymentMethod: "Selecionar Método de Pagamento",
    cryptocurrency: "Criptomoeda", bankTransfer: "Transferência Bancária", eWallets: "Carteiras Digitais",
    walletAddress: "Endereço da Carteira", paymentDetails: "Detalhes do Pagamento",
    afterSending: "Após enviar, submeta seu ID de transação via suporte. Creditado em 30–60 minutos.",
    iSent: "Já Enviei o Pagamento →",
    withdrawFunds: "Sacar Fundos", availableBalance2: "Saldo Disponível",
    selectAccount: "Selecionar Conta de Saque", enterAmount: "Inserir Valor",
    processingFee: "Taxa de processamento (1.5%)", youReceive: "Você recebe",
    confirmWithdrawal: "Confirmar Saque", submitWithdrawal: "Enviar Pedido de Saque",
    myAccounts: "Minhas Contas", addAccount: "Adicionar Conta",
    accountLabel: "Rótulo da Conta", accountType: "Tipo de Conta",
    bankName: "Nome do Banco", accountHolderName: "Nome do Titular",
    accountNumber: "Número da Conta", routingNumber: "Número de Roteamento",
    swiftCode: "Código SWIFT / BIC", ibanLabel: "IBAN",
    saveAccount: "Salvar Conta", noAccountsYet: "Nenhuma Conta Adicionada",
    hereToHelp: "Estamos Aqui para Ajudar", fastResponse: "Resposta Rápida",
    available247: "Disponível 24/7", securePrivate: "Seguro e Privado",
    faqTitle: "Perguntas Frequentes", sendMessage: "Enviar Mensagem",
    yourName: "Seu Nome", subject: "Assunto", message: "Mensagem",
    sendBtn: "Enviar →", messageSent: "Mensagem enviada! Responderemos em 24 horas.",
    notificationsTitle: "Notificações", allCaughtUp: "Tudo em dia!",
    unread: "não lida", total: "total", markAllRead: "Marcar todas como lidas",
    noNotifications: "Sem Notificações", markRead: "Marcar como lida",
    globalPlatform: "Plataforma de Investimento Global — Atendendo investidores em mais de 150 países",
    riskWarning: "Investir envolve riscos. Desempenho passado não garante resultados futuros.",
  },

  hi: {
    plans: "योजनाएं", howItWorks: "यह कैसे काम करता है", referrals: "रेफरल", about: "के बारे में",
    signIn: "साइन इन", getStarted: "शुरू करें",
    heroTitle: "हर सीमा के पार अपनी संपत्ति बढ़ाएं",
    heroSub: "150+ देशों के निवेशकों के साथ जुड़ें जो हमारे पेशेवर रूप से प्रबंधित निवेश पोर्टफोलियो के साथ लगातार रिटर्न अर्जित कर रहे हैं।",
    startInvesting: "आज निवेश शुरू करें", viewPlans: "योजनाएं देखें",
    totalManaged: "कुल प्रबंधित", activeInvestors: "सक्रिय निवेशक",
    payoutRate: "भुगतान दर", countries: "देश",
    investmentPlans: "निवेश योजनाएं", chooseGrowthPath: "अपना विकास पथ चुनें",
    plansDesc: "वह योजना चुनें जो आपके लक्ष्यों से मेल खाती हो। सभी योजनाओं में दैनिक लाभ ट्रैकिंग और 24/7 सहायता शामिल है।",
    roiLabel: "ROI", overDays: "{n} दिनों में", minLabel: "न्यूनतम", maxLabel: "अधिकतम",
    dailyUpdates: "दैनिक लाभ अपडेट", support247: "24/7 सहायता",
    instantWithdrawal: "तत्काल निकासी", investNow: "अभी निवेश करें →",
    howItWorksTitle: "यह कैसे काम करता है", threeSteps: "तीन सरल चरणों में कमाना शुरू करें",
    step1Title: "खाता बनाएं", step1Desc: "केवल अपने ईमेल से 2 मिनट से कम में साइन अप करें।",
    step2Title: "फंड जमा करें", step2Desc: "बिटकॉइन, एथेरियम, USDT, बैंक ट्रांसफर या ई-वॉलेट के माध्यम से फंड करें।",
    step3Title: "रिटर्न अर्जित करें", step3Desc: "आपका पैसा 24/7 काम करता है। रीयल-टाइम में कमाई ट्रैक करें।",
    referralProgram: "रेफरल प्रोग्राम", earnWhileShare: "शेयर करते हुए कमाएं",
    referralDesc: "दोस्तों को आमंत्रित करें और 3 स्तरों पर कमाएं।",
    directReferrals: "प्रत्यक्ष रेफरल", theirReferrals: "उनके रेफरल", thirdGen: "तीसरी पीढ़ी",
    getReferralLink: "मेरा रेफरल लिंक पाएं →",
    welcomeBack: "वापस स्वागत है", signInAccount: "अपने निवेश खाते में साइन इन करें",
    createAccount: "खाता बनाएं", join14k: "14,000+ वैश्विक निवेशकों से जुड़ें",
    fullName: "पूरा नाम", emailAddress: "ईमेल पता", country: "देश",
    password: "पासवर्ड", confirmPassword: "पासवर्ड की पुष्टि करें",
    referralCode: "रेफरल कोड (वैकल्पिक)", alreadyHave: "पहले से खाता है?",
    dontHave: "खाता नहीं है?", signUp: "साइन अप",
    overview: "अवलोकन", invest: "निवेश", deposit: "जमा",
    withdraw: "निकासी", history: "इतिहास", support: "सहायता", notifications: "सूचनाएं",
    availableBalance: "उपलब्ध शेष", totalInvested: "कुल निवेश",
    totalEarned: "कुल अर्जित", referralEarnings: "रेफरल आय",
    activeInvestment: "सक्रिय निवेश", quickActions: "त्वरित कार्य",
    recentTransactions: "हालिया लेनदेन", viewAll: "सभी देखें",
    selectPlan: "योजना चुनें", configureInvestment: "निवेश कॉन्फ़िगर करें",
    investmentAmount: "निवेश राशि (USD)", expectedProfit: "अपेक्षित लाभ",
    totalReturn: "कुल रिटर्न", confirmInvestment: "निवेश की पुष्टि करें →",
    depositFunds: "फंड जमा करें", selectPaymentMethod: "भुगतान विधि चुनें",
    cryptocurrency: "क्रिप्टोकरेंसी", bankTransfer: "बैंक ट्रांसफर", eWallets: "ई-वॉलेट",
    walletAddress: "वॉलेट पता", paymentDetails: "भुगतान विवरण",
    afterSending: "भेजने के बाद, सहायता के माध्यम से अपना लेनदेन ID सबमिट करें। 30-60 मिनट में क्रेडिट होगा।",
    iSent: "मैंने भुगतान भेज दिया →",
    withdrawFunds: "फंड निकालें", availableBalance2: "उपलब्ध शेष",
    selectAccount: "निकासी खाता चुनें", enterAmount: "राशि दर्ज करें",
    processingFee: "प्रसंस्करण शुल्क (1.5%)", youReceive: "आपको मिलेगा",
    confirmWithdrawal: "निकासी की पुष्टि करें", submitWithdrawal: "निकासी अनुरोध सबमिट करें",
    myAccounts: "मेरे खाते", addAccount: "खाता जोड़ें",
    accountLabel: "खाता लेबल", accountType: "खाता प्रकार",
    bankName: "बैंक का नाम", accountHolderName: "खाताधारक का नाम",
    accountNumber: "खाता संख्या", routingNumber: "रूटिंग नंबर",
    swiftCode: "SWIFT / BIC कोड", ibanLabel: "IBAN",
    saveAccount: "खाता सहेजें", noAccountsYet: "अभी तक कोई खाता नहीं जोड़ा",
    hereToHelp: "हम मदद के लिए यहां हैं", fastResponse: "त्वरित प्रतिक्रिया",
    available247: "24/7 उपलब्ध", securePrivate: "सुरक्षित और निजी",
    faqTitle: "अक्सर पूछे जाने वाले प्रश्न", sendMessage: "संदेश भेजें",
    yourName: "आपका नाम", subject: "विषय", message: "संदेश",
    sendBtn: "भेजें →", messageSent: "संदेश भेजा गया! हम 24 घंटे के भीतर जवाब देंगे।",
    notificationsTitle: "सूचनाएं", allCaughtUp: "सब अपडेट है!",
    unread: "अपठित", total: "कुल", markAllRead: "सभी को पढ़ा हुआ चिह्नित करें",
    noNotifications: "कोई सूचना नहीं", markRead: "पढ़ा हुआ चिह्नित करें",
    globalPlatform: "वैश्विक निवेश मंच — 150+ देशों में निवेशकों की सेवा",
    riskWarning: "निवेश में जोखिम शामिल है। पिछला प्रदर्शन भविष्य के परिणामों की गारंटी नहीं देता।",
  },

  ru: {
    plans: "Планы", howItWorks: "Как Это Работает", referrals: "Рефералы", about: "О Нас",
    signIn: "Войти", getStarted: "Начать",
    heroTitle: "Приумножьте Капитал Без Границ",
    heroSub: "Присоединяйтесь к инвесторам из более чем 150 стран, получающим стабильный доход с нашими профессионально управляемыми портфелями.",
    startInvesting: "Начать Инвестировать", viewPlans: "Просмотреть Планы",
    totalManaged: "Под Управлением", activeInvestors: "Активных Инвесторов",
    payoutRate: "Ставка Выплат", countries: "Стран",
    investmentPlans: "Инвестиционные Планы", chooseGrowthPath: "Выберите Путь Роста",
    plansDesc: "Выберите план, соответствующий вашим целям. Все планы включают ежедневное отслеживание прибыли и поддержку 24/7.",
    roiLabel: "ROI", overDays: "За {n} дней", minLabel: "Мин", maxLabel: "Макс",
    dailyUpdates: "Ежедневные обновления прибыли", support247: "Поддержка 24/7",
    instantWithdrawal: "Мгновенный вывод", investNow: "Инвестировать Сейчас →",
    howItWorksTitle: "Как Это Работает", threeSteps: "Начните зарабатывать за три простых шага",
    step1Title: "Создать Аккаунт", step1Desc: "Зарегистрируйтесь менее чем за 2 минуты с вашим email.",
    step2Title: "Пополнить Счёт", step2Desc: "Пополните через Bitcoin, Ethereum, USDT, банковский перевод или электронный кошелёк.",
    step3Title: "Получать Доход", step3Desc: "Ваши деньги работают 24/7. Отслеживайте доходы в реальном времени.",
    referralProgram: "Реферальная Программа", earnWhileShare: "Зарабатывайте Делясь",
    referralDesc: "Приглашайте друзей и зарабатывайте на 3 уровнях.",
    directReferrals: "Прямые рефералы", theirReferrals: "Их рефералы", thirdGen: "3-е поколение",
    getReferralLink: "Получить Реферальную Ссылку →",
    welcomeBack: "Добро пожаловать обратно", signInAccount: "Войдите в свой инвестиционный аккаунт",
    createAccount: "Создать Аккаунт", join14k: "Присоединяйтесь к 14 000+ глобальных инвесторов",
    fullName: "Полное Имя", emailAddress: "Email Адрес", country: "Страна",
    password: "Пароль", confirmPassword: "Подтвердить Пароль",
    referralCode: "Реферальный Код (необязательно)", alreadyHave: "Уже есть аккаунт?",
    dontHave: "Нет аккаунта?", signUp: "Зарегистрироваться",
    overview: "Обзор", invest: "Инвестировать", deposit: "Пополнить",
    withdraw: "Вывести", history: "История", support: "Поддержка", notifications: "Уведомления",
    availableBalance: "Доступный Баланс", totalInvested: "Всего Инвестировано",
    totalEarned: "Всего Заработано", referralEarnings: "Реферальный Доход",
    activeInvestment: "Активная Инвестиция", quickActions: "Быстрые Действия",
    recentTransactions: "Последние Транзакции", viewAll: "Просмотреть Всё",
    selectPlan: "Выбрать План", configureInvestment: "Настроить Инвестицию",
    investmentAmount: "Сумма Инвестиции (USD)", expectedProfit: "Ожидаемая Прибыль",
    totalReturn: "Общий Доход", confirmInvestment: "Подтвердить Инвестицию →",
    depositFunds: "Пополнить Счёт", selectPaymentMethod: "Выбрать Способ Оплаты",
    cryptocurrency: "Криптовалюта", bankTransfer: "Банковский Перевод", eWallets: "Электронные Кошельки",
    walletAddress: "Адрес Кошелька", paymentDetails: "Платёжные Данные",
    afterSending: "После отправки предоставьте ID транзакции через поддержку. Зачисление за 30–60 минут.",
    iSent: "Я Отправил Платёж →",
    withdrawFunds: "Вывести Средства", availableBalance2: "Доступный Баланс",
    selectAccount: "Выбрать Счёт для Вывода", enterAmount: "Введите Сумму",
    processingFee: "Комиссия за обработку (1.5%)", youReceive: "Вы получите",
    confirmWithdrawal: "Подтвердить Вывод", submitWithdrawal: "Отправить Запрос на Вывод",
    myAccounts: "Мои Счета", addAccount: "Добавить Счёт",
    accountLabel: "Название Счёта", accountType: "Тип Счёта",
    bankName: "Название Банка", accountHolderName: "Имя Владельца Счёта",
    accountNumber: "Номер Счёта", routingNumber: "Маршрутный Номер",
    swiftCode: "Код SWIFT / BIC", ibanLabel: "IBAN",
    saveAccount: "Сохранить Счёт", noAccountsYet: "Счета ещё не добавлены",
    hereToHelp: "Мы Здесь, Чтобы Помочь", fastResponse: "Быстрый Ответ",
    available247: "Доступно 24/7", securePrivate: "Безопасно и Конфиденциально",
    faqTitle: "Часто Задаваемые Вопросы", sendMessage: "Отправить Сообщение",
    yourName: "Ваше Имя", subject: "Тема", message: "Сообщение",
    sendBtn: "Отправить →", messageSent: "Сообщение отправлено! Мы ответим в течение 24 часов.",
    notificationsTitle: "Уведомления", allCaughtUp: "Всё прочитано!",
    unread: "непрочитанных", total: "всего", markAllRead: "Отметить все как прочитанные",
    noNotifications: "Нет Уведомлений", markRead: "Отметить прочитанным",
    globalPlatform: "Глобальная Инвестиционная Платформа — Обслуживаем инвесторов в более чем 150 странах",
    riskWarning: "Инвестирование сопряжено с рисками. Прошлые результаты не гарантируют будущих.",
  },

  id: {
    plans: "Paket", howItWorks: "Cara Kerja", referrals: "Referral", about: "Tentang",
    signIn: "Masuk", getStarted: "Mulai",
    heroTitle: "Kembangkan Kekayaan Anda Tanpa Batas",
    heroSub: "Bergabunglah dengan investor dari 150+ negara yang mendapatkan imbal hasil konsisten dengan portofolio kami yang dikelola secara profesional.",
    startInvesting: "Mulai Berinvestasi Hari Ini", viewPlans: "Lihat Paket",
    totalManaged: "Total Dikelola", activeInvestors: "Investor Aktif",
    payoutRate: "Tingkat Pembayaran", countries: "Negara",
    investmentPlans: "Paket Investasi", chooseGrowthPath: "Pilih Jalur Pertumbuhan Anda",
    plansDesc: "Pilih paket yang sesuai dengan tujuan investasi Anda. Semua paket mencakup pelacakan keuntungan harian dan dukungan 24/7.",
    roiLabel: "ROI", overDays: "Selama {n} hari", minLabel: "Min", maxLabel: "Maks",
    dailyUpdates: "Pembaruan keuntungan harian", support247: "Dukungan 24/7",
    instantWithdrawal: "Penarikan instan", investNow: "Investasi Sekarang →",
    howItWorksTitle: "Cara Kerja", threeSteps: "Mulai menghasilkan dalam tiga langkah sederhana",
    step1Title: "Buat Akun", step1Desc: "Daftar dalam waktu kurang dari 2 menit hanya dengan email Anda.",
    step2Title: "Setor Dana", step2Desc: "Danai akun Anda melalui Bitcoin, Ethereum, USDT, transfer bank, atau e-wallet.",
    step3Title: "Dapatkan Imbal Hasil", step3Desc: "Uang Anda bekerja 24/7. Pantau penghasilan secara real-time dan tarik kapan saja.",
    referralProgram: "Program Referral", earnWhileShare: "Hasilkan Sambil Berbagi",
    referralDesc: "Undang teman dan dapatkan komisi di 3 level.",
    directReferrals: "Referral langsung", theirReferrals: "Referral mereka", thirdGen: "Generasi ke-3",
    getReferralLink: "Dapatkan Link Referral Saya →",
    welcomeBack: "Selamat datang kembali", signInAccount: "Masuk ke akun investasi Anda",
    createAccount: "Buat Akun", join14k: "Bergabung dengan 14.000+ investor global",
    fullName: "Nama Lengkap", emailAddress: "Alamat Email", country: "Negara",
    password: "Kata Sandi", confirmPassword: "Konfirmasi Kata Sandi",
    referralCode: "Kode Referral (opsional)", alreadyHave: "Sudah punya akun?",
    dontHave: "Belum punya akun?", signUp: "Daftar",
    overview: "Ikhtisar", invest: "Investasi", deposit: "Setor",
    withdraw: "Tarik", history: "Riwayat", support: "Dukungan", notifications: "Notifikasi",
    availableBalance: "Saldo Tersedia", totalInvested: "Total Diinvestasikan",
    totalEarned: "Total Diperoleh", referralEarnings: "Pendapatan Referral",
    activeInvestment: "Investasi Aktif", quickActions: "Tindakan Cepat",
    recentTransactions: "Transaksi Terbaru", viewAll: "Lihat Semua",
    selectPlan: "Pilih Paket", configureInvestment: "Konfigurasi Investasi",
    investmentAmount: "Jumlah Investasi (USD)", expectedProfit: "Keuntungan yang Diharapkan",
    totalReturn: "Total Pengembalian", confirmInvestment: "Konfirmasi Investasi →",
    depositFunds: "Setor Dana", selectPaymentMethod: "Pilih Metode Pembayaran",
    cryptocurrency: "Cryptocurrency", bankTransfer: "Transfer Bank", eWallets: "E-Wallet",
    walletAddress: "Alamat Dompet", paymentDetails: "Detail Pembayaran",
    afterSending: "Setelah mengirim, kirimkan ID transaksi Anda melalui dukungan. Dikreditkan dalam 30–60 menit.",
    iSent: "Saya Sudah Mengirim Pembayaran →",
    withdrawFunds: "Tarik Dana", availableBalance2: "Saldo Tersedia",
    selectAccount: "Pilih Akun Penarikan", enterAmount: "Masukkan Jumlah",
    processingFee: "Biaya pemrosesan (1.5%)", youReceive: "Anda terima",
    confirmWithdrawal: "Konfirmasi Penarikan", submitWithdrawal: "Kirim Permintaan Penarikan",
    myAccounts: "Akun Saya", addAccount: "Tambah Akun",
    accountLabel: "Label Akun", accountType: "Jenis Akun",
    bankName: "Nama Bank", accountHolderName: "Nama Pemegang Akun",
    accountNumber: "Nomor Akun", routingNumber: "Nomor Routing",
    swiftCode: "Kode SWIFT / BIC", ibanLabel: "IBAN",
    saveAccount: "Simpan Akun", noAccountsYet: "Belum Ada Akun yang Ditambahkan",
    hereToHelp: "Kami Siap Membantu", fastResponse: "Respons Cepat",
    available247: "Tersedia 24/7", securePrivate: "Aman & Privat",
    faqTitle: "Pertanyaan yang Sering Diajukan", sendMessage: "Kirim Pesan",
    yourName: "Nama Anda", subject: "Subjek", message: "Pesan",
    sendBtn: "Kirim →", messageSent: "Pesan terkirim! Kami akan membalas dalam 24 jam.",
    notificationsTitle: "Notifikasi", allCaughtUp: "Semua sudah terbaca!",
    unread: "belum dibaca", total: "total", markAllRead: "Tandai semua sudah dibaca",
    noNotifications: "Tidak Ada Notifikasi", markRead: "Tandai sudah dibaca",
    globalPlatform: "Platform Investasi Global — Melayani investor di 150+ negara",
    riskWarning: "Investasi melibatkan risiko. Kinerja masa lalu tidak menjamin hasil di masa depan.",
  },

  tr: {
    plans: "Planlar", howItWorks: "Nasıl Çalışır", referrals: "Referanslar", about: "Hakkında",
    signIn: "Giriş Yap", getStarted: "Başla",
    heroTitle: "Servetinizi Her Sınırda Büyütün",
    heroSub: "150'den fazla ülkeden yatırımcılara katılın ve profesyonelce yönetilen portföylerimizle tutarlı getiriler elde edin.",
    startInvesting: "Bugün Yatırıma Başla", viewPlans: "Planları Görüntüle",
    totalManaged: "Toplam Yönetilen", activeInvestors: "Aktif Yatırımcılar",
    payoutRate: "Ödeme Oranı", countries: "Ülke",
    investmentPlans: "Yatırım Planları", chooseGrowthPath: "Büyüme Yolunuzu Seçin",
    plansDesc: "Hedeflerinize uygun planı seçin. Tüm planlar günlük kar takibi ve 7/24 destek içerir.",
    roiLabel: "ROI", overDays: "{n} gün içinde", minLabel: "Min", maxLabel: "Maks",
    dailyUpdates: "Günlük kar güncellemeleri", support247: "7/24 destek",
    instantWithdrawal: "Anında çekim", investNow: "Şimdi Yatır →",
    howItWorksTitle: "Nasıl Çalışır", threeSteps: "Üç basit adımda kazanmaya başlayın",
    step1Title: "Hesap Oluştur", step1Desc: "Sadece e-postanızla 2 dakikadan kısa sürede kaydolun.",
    step2Title: "Fon Yatır", step2Desc: "Bitcoin, Ethereum, USDT, banka havalesi veya e-cüzdan ile hesabınızı finanse edin.",
    step3Title: "Getiri Elde Et", step3Desc: "Paranız 7/24 çalışır. Kazançlarınızı gerçek zamanlı takip edin.",
    referralProgram: "Referans Programı", earnWhileShare: "Paylaşırken Kazan",
    referralDesc: "Arkadaşlarınızı davet edin ve 3 seviyede komisyon kazanın.",
    directReferrals: "Doğrudan referanslar", theirReferrals: "Onların referansları", thirdGen: "3. nesil",
    getReferralLink: "Referans Linkimi Al →",
    welcomeBack: "Tekrar hoş geldiniz", signInAccount: "Yatırım hesabınıza giriş yapın",
    createAccount: "Hesap Oluştur", join14k: "14.000'den fazla küresel yatırımcıya katılın",
    fullName: "Tam Ad", emailAddress: "E-posta Adresi", country: "Ülke",
    password: "Şifre", confirmPassword: "Şifreyi Onayla",
    referralCode: "Referans Kodu (isteğe bağlı)", alreadyHave: "Hesabınız var mı?",
    dontHave: "Hesabınız yok mu?", signUp: "Kaydol",
    overview: "Genel Bakış", invest: "Yatır", deposit: "Para Yatır",
    withdraw: "Çek", history: "Geçmiş", support: "Destek", notifications: "Bildirimler",
    availableBalance: "Kullanılabilir Bakiye", totalInvested: "Toplam Yatırılan",
    totalEarned: "Toplam Kazanılan", referralEarnings: "Referans Kazançları",
    activeInvestment: "Aktif Yatırım", quickActions: "Hızlı İşlemler",
    recentTransactions: "Son İşlemler", viewAll: "Tümünü Gör",
    selectPlan: "Plan Seç", configureInvestment: "Yatırımı Yapılandır",
    investmentAmount: "Yatırım Tutarı (USD)", expectedProfit: "Beklenen Kâr",
    totalReturn: "Toplam Getiri", confirmInvestment: "Yatırımı Onayla →",
    depositFunds: "Para Yatır", selectPaymentMethod: "Ödeme Yöntemi Seç",
    cryptocurrency: "Kripto Para", bankTransfer: "Banka Havalesi", eWallets: "E-Cüzdanlar",
    walletAddress: "Cüzdan Adresi", paymentDetails: "Ödeme Detayları",
    afterSending: "Gönderdikten sonra işlem ID'nizi destek aracılığıyla gönderin. 30-60 dakika içinde yansır.",
    iSent: "Ödemeyi Gönderdim →",
    withdrawFunds: "Para Çek", availableBalance2: "Kullanılabilir Bakiye",
    selectAccount: "Çekim Hesabı Seç", enterAmount: "Tutar Gir",
    processingFee: "İşlem ücreti (1.5%)", youReceive: "Alacağınız",
    confirmWithdrawal: "Çekimi Onayla", submitWithdrawal: "Çekim Talebi Gönder",
    myAccounts: "Hesaplarım", addAccount: "Hesap Ekle",
    accountLabel: "Hesap Etiketi", accountType: "Hesap Türü",
    bankName: "Banka Adı", accountHolderName: "Hesap Sahibinin Adı",
    accountNumber: "Hesap Numarası", routingNumber: "Yönlendirme Numarası",
    swiftCode: "SWIFT / BIC Kodu", ibanLabel: "IBAN",
    saveAccount: "Hesabı Kaydet", noAccountsYet: "Henüz Hesap Eklenmedi",
    hereToHelp: "Yardım İçin Buradayız", fastResponse: "Hızlı Yanıt",
    available247: "7/24 Erişilebilir", securePrivate: "Güvenli ve Gizli",
    faqTitle: "Sık Sorulan Sorular", sendMessage: "Mesaj Gönder",
    yourName: "Adınız", subject: "Konu", message: "Mesaj",
    sendBtn: "Gönder →", messageSent: "Mesaj gönderildi! 24 saat içinde yanıt vereceğiz.",
    notificationsTitle: "Bildirimler", allCaughtUp: "Hepsi okundu!",
    unread: "okunmamış", total: "toplam", markAllRead: "Tümünü okundu işaretle",
    noNotifications: "Bildirim Yok", markRead: "Okundu işaretle",
    globalPlatform: "Küresel Yatırım Platformu — 150'den fazla ülkede yatırımcılara hizmet",
    riskWarning: "Yatırım risk içerir. Geçmiş performans gelecekteki sonuçları garanti etmez.",
  },
};

// Language Context
const LangContext = createContext({ lang: "en", t: (k) => k, setLang: () => {} });
const useLang = () => useContext(LangContext);

// Translation hook
const useT = () => {
  const { lang } = useLang();
  return (key, vars = {}) => {
    const dict = TRANSLATIONS[lang] || TRANSLATIONS.en;
    let str = dict[key] || TRANSLATIONS.en[key] || key;
    Object.entries(vars).forEach(([k, v]) => { str = str.replace(`{${k}}`, v); });
    return str;
  };
};

// Language Selector component
function LanguageSelector({ compact = false }) {
  const { lang, setLang } = useLang();
  const [open, setOpen] = useState(false);
  const current = LANGUAGES.find(l => l.code === lang) || LANGUAGES[0];

  return (
    <div style={{ position: "relative", display: "inline-block" }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "rgba(255,255,255,0.06)", border: "1px solid #1C2538",
          borderRadius: 8, padding: compact ? "5px 10px" : "7px 12px",
          color: "#E8EBF3", cursor: "pointer", fontSize: 13, fontWeight: 600,
          fontFamily: "inherit",
        }}
      >
        <span style={{ fontSize: 16 }}>{current.flag}</span>
        {!compact && <span>{current.name}</span>}
        <span style={{ color: "#9DAED0", fontSize: 10 }}>▼</span>
      </button>
      {open && (
        <div style={{
          position: "absolute", top: "110%", right: 0, zIndex: 999,
          background: "#111827", border: "1px solid #1C2538", borderRadius: 12,
          padding: 6, minWidth: 180, boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        }}>
          {LANGUAGES.map(l => (
            <button key={l.code} onClick={() => { setLang(l.code); setOpen(false); }}
              style={{
                display: "flex", alignItems: "center", gap: 10, width: "100%",
                padding: "9px 12px", borderRadius: 8, border: "none", cursor: "pointer",
                background: lang === l.code ? "rgba(26,86,219,0.2)" : "transparent",
                color: lang === l.code ? "#60A5FA" : "#E8EBF3",
                fontSize: 13, fontWeight: lang === l.code ? 700 : 400, fontFamily: "inherit",
                textAlign: "left",
              }}
            >
              <span style={{ fontSize: 18 }}>{l.flag}</span>
              <span style={{ flex: 1 }}>{l.name}</span>
              {lang === l.code && <span style={{ color: "#60A5FA" }}>✓</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Palette & Design Tokens ──────────────────────────────────────────────────
// Deep navy (#0A0F1E) base, electric gold (#F5C842) accent, slate (#1C2538) cards
// Display: "Space Grotesk" feel via system-ui bold; body: clean sans
// Signature: animated ticker + live yield counter + glowing CTA

// ── Mock Data ────────────────────────────────────────────────────────────────
const PLANS = [
  { id: 1, name: "Starter", min: 100, max: 999, roi: 5, duration: 7, color: "#4ADE80" },
  { id: 2, name: "Growth", min: 1000, max: 4999, roi: 10, duration: 14, color: "#F5C842" },
  { id: 3, name: "Premium", min: 5000, max: 19999, roi: 18, duration: 21, color: "#A78BFA" },
  { id: 4, name: "Elite", min: 20000, max: 99999, roi: 28, duration: 30, color: "#F87171" },
  { id: 5, name: "Sovereign", min: 100000, max: Infinity, roi: 40, duration: 60, color: "#38BDF8" },
];

const PAYMENT_METHODS = [
  { id: "btc", name: "Bitcoin (BTC)", icon: "₿", network: "Bitcoin Network", placeholder: "bc1q..." },
  { id: "eth", name: "Ethereum (ETH)", icon: "Ξ", network: "ERC-20", placeholder: "0x..." },
  { id: "usdt_trc20", name: "USDT (TRC-20)", icon: "₮", network: "Tron Network", placeholder: "T..." },
  { id: "usdt_erc20", name: "USDT (ERC-20)", icon: "₮", network: "Ethereum", placeholder: "0x..." },
  { id: "bnb", name: "BNB", icon: "◈", network: "BEP-20", placeholder: "0x..." },
  { id: "sol", name: "Solana (SOL)", icon: "◎", network: "Solana", placeholder: "..." },
  { id: "xrp", name: "XRP (Ripple)", icon: "✕", network: "XRP Ledger", placeholder: "r..." },
  { id: "paypal", name: "PayPal", icon: "P", network: "PayPal", placeholder: "email@..." },
  { id: "bank_wire", name: "Bank Wire Transfer", icon: "🏦", network: "SWIFT/SEPA", placeholder: "IBAN / Account No." },
  { id: "cashapp", name: "Cash App", icon: "$", network: "US / UK", placeholder: "$cashtag" },
  { id: "skrill", name: "Skrill", icon: "S", network: "Global", placeholder: "email@..." },
  { id: "neteller", name: "Neteller", icon: "N", network: "Global", placeholder: "email / ID" },
  { id: "perfect_money", name: "Perfect Money", icon: "PM", network: "Global", placeholder: "U..." },
];

const TICKERS = [
  "BTC $67,420 +2.4%", "ETH $3,812 +1.8%", "BNB $598 +0.9%",
  "SOL $178 +5.2%", "XRP $0.62 +3.1%", "USDT $1.00 +0.01%",
  "Total Investors: 84,321", "Payouts Today: $2.4M", "Uptime: 99.98%",
];

// ── Persistent Storage (localStorage) ────────────────────────────────────────
const DB_KEY = "nexavest_db_v1";

const defaultDb = {
  users: {},
  paymentDetails: Object.fromEntries(PAYMENT_METHODS.map(p => [p.id, { address: "", note: "" }])),
  investments: [],
  withdrawals: [],
  referrals: [],
  notifications: [],
  socialLinks: {
    whatsapp: "",
    telegram: "",
    tiktok: "",
    whatsappLabel: "Chat on WhatsApp",
    telegramLabel: "Join Telegram Channel",
    tiktokLabel: "Follow on TikTok",
  },
};

// Helper: push a notification to a user
const pushNotification = (userId, { title, message, type = "info", txnId = null }) => {
  const d = db.get();
  if (!d.notifications) d.notifications = [];
  d.notifications.push({
    id: Math.random().toString(36).slice(2),
    userId,
    title,
    message,
    type,        // "success" | "error" | "info" | "warning"
    txnId,
    read: false,
    date: new Date().toISOString(),
  });
  db.save(d);
};

const db = {
  get: () => {
    try {
      const raw = localStorage.getItem(DB_KEY);
      if (!raw) return { ...defaultDb, paymentDetails: Object.fromEntries(PAYMENT_METHODS.map(p => [p.id, { address: "", note: "" }])) };
      const parsed = JSON.parse(raw);
      // Merge with defaults so new fields added in updates always exist
      return {
        ...defaultDb,
        ...parsed,
        paymentDetails: { ...defaultDb.paymentDetails, ...(parsed.paymentDetails || {}) },
        socialLinks: { ...defaultDb.socialLinks, ...(parsed.socialLinks || {}) },
        notifications: parsed.notifications || [],
      };
    } catch (e) {
      console.error("DB read error", e);
      return { ...defaultDb };
    }
  },
  save: (data) => {
    try {
      const current = db.get();
      const merged = { ...current, ...data };
      localStorage.setItem(DB_KEY, JSON.stringify(merged));
    } catch (e) {
      console.error("DB save error", e);
    }
  },
  clear: () => {
    try { localStorage.removeItem(DB_KEY); } catch (e) {}
  },
};

// ── Utility ──────────────────────────────────────────────────────────────────
const genId = () => Math.random().toString(36).slice(2, 10).toUpperCase();
const genRef = (name) => name.replace(/\s/g, "").slice(0, 5).toUpperCase() + genId().slice(0, 4);
const fmt = (n) => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(n);
const fmtNum = (n) => new Intl.NumberFormat("en-US").format(n);

// ── Styles ───────────────────────────────────────────────────────────────────
const S = {
  app: {
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    background: "#0A0F1E",
    color: "#E8EBF3",
    minHeight: "100vh",
  },
  nav: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "0 2rem", height: 64, background: "#0D1427",
    borderBottom: "1px solid #1C2538", position: "sticky", top: 0, zIndex: 100,
  },
  logo: { fontSize: 22, fontWeight: 800, color: "#F5C842", letterSpacing: -0.5 },
  navLinks: { display: "flex", gap: 8 },
  navBtn: (active) => ({
    padding: "6px 16px", borderRadius: 8, border: "none", cursor: "pointer",
    fontWeight: 600, fontSize: 14, transition: "all .2s",
    background: active ? "#F5C842" : "transparent",
    color: active ? "#0A0F1E" : "#9DAED0",
  }),
  ticker: {
    background: "#F5C842", color: "#0A0F1E", padding: "6px 0",
    fontSize: 13, fontWeight: 700, overflow: "hidden", whiteSpace: "nowrap",
  },
  page: { maxWidth: 1200, margin: "0 auto", padding: "2rem 1.5rem" },
  hero: {
    textAlign: "center", padding: "5rem 1rem 3rem",
    background: "radial-gradient(ellipse at 50% 0%, #1a2a4a 0%, #0A0F1E 70%)",
  },
  h1: { fontSize: "clamp(2rem,5vw,3.5rem)", fontWeight: 900, lineHeight: 1.1, margin: "0 0 1rem" },
  gold: { color: "#F5C842" },
  sub: { fontSize: 18, color: "#9DAED0", maxWidth: 600, margin: "0 auto 2rem" },
  btn: (variant = "primary") => ({
    padding: variant === "sm" ? "8px 18px" : "14px 32px",
    borderRadius: 10, border: "none", cursor: "pointer", fontWeight: 700,
    fontSize: variant === "sm" ? 13 : 16, transition: "all .2s",
    background: variant === "primary" ? "#F5C842" : variant === "danger" ? "#EF4444" : "#1C2538",
    color: variant === "primary" ? "#0A0F1E" : "#E8EBF3",
    boxShadow: variant === "primary" ? "0 0 20px #F5C84255" : "none",
  }),
  card: {
    background: "#111827", border: "1px solid #1C2538", borderRadius: 16,
    padding: "1.5rem", marginBottom: "1rem",
  },
  planCard: (color) => ({
    background: "#111827", border: `1px solid ${color}40`,
    borderRadius: 16, padding: "1.5rem", cursor: "pointer",
    transition: "all .2s", position: "relative", overflow: "hidden",
  }),
  badge: (color) => ({
    display: "inline-block", padding: "3px 10px", borderRadius: 20,
    fontSize: 12, fontWeight: 700, background: color + "22", color,
  }),
  input: {
    width: "100%", padding: "10px 14px", borderRadius: 10, border: "1px solid #1C2538",
    background: "#0D1427", color: "#E8EBF3", fontSize: 15, outline: "none",
    boxSizing: "border-box",
  },
  label: { fontSize: 13, fontWeight: 600, color: "#9DAED0", display: "block", marginBottom: 6 },
  grid2: { display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: "1rem" },
  grid3: { display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: "1rem" },
  stat: {
    background: "#111827", border: "1px solid #1C2538", borderRadius: 12,
    padding: "1.2rem 1.5rem",
  },
  tab: (active) => ({
    padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer",
    fontWeight: 600, fontSize: 14,
    background: active ? "#1C2538" : "transparent",
    color: active ? "#F5C842" : "#9DAED0",
  }),
  table: { width: "100%", borderCollapse: "collapse", fontSize: 14 },
  th: { textAlign: "left", padding: "10px 12px", color: "#9DAED0", borderBottom: "1px solid #1C2538", fontWeight: 600 },
  td: { padding: "12px", borderBottom: "1px solid #0D1427" },
  toast: (type) => ({
    position: "fixed", bottom: 24, right: 24, zIndex: 999,
    padding: "14px 22px", borderRadius: 12, fontWeight: 600, fontSize: 15,
    background: type === "success" ? "#166534" : type === "error" ? "#7f1d1d" : "#1C2538",
    color: "#fff", boxShadow: "0 8px 32px #00000066",
    border: `1px solid ${type === "success" ? "#4ADE80" : type === "error" ? "#F87171" : "#374151"}`,
  }),
  modal: {
    position: "fixed", inset: 0, background: "#00000088", zIndex: 200,
    display: "flex", alignItems: "center", justifyContent: "center",
  },
  modalBox: {
    background: "#111827", border: "1px solid #1C2538", borderRadius: 20,
    padding: "2rem", maxWidth: 480, width: "90%", maxHeight: "90vh", overflowY: "auto",
  },
  status: (s) => ({
    display: "inline-block", padding: "2px 10px", borderRadius: 20, fontSize: 12, fontWeight: 700,
    background: s === "active" ? "#14532d" : s === "completed" ? "#1e3a5f" : s === "pending" ? "#713f12" : "#7f1d1d",
    color: s === "active" ? "#4ADE80" : s === "completed" ? "#60A5FA" : s === "pending" ? "#FCD34D" : "#F87171",
  }),
};

// ════════════════════════════════════════════════════════════════════════════
// MAIN APP
// ════════════════════════════════════════════════════════════════════════════
export default function App() {
  const [page, setPage] = useState("home");
  const [user, setUser] = useState(() => {
    try {
      const sessionUser = sessionManager.get();
      if (!sessionUser) return null;
      if (sessionUser?.isAdmin) return sessionUser;
      const dbUser = db.get().users?.[sessionUser?.email];
      return dbUser || null;
    } catch { return null; }
  });
  const [toast, setToast] = useState(null);
  const [modal, setModal] = useState(null);

  const showToast = useCallback((msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  }, []);

  const logout = () => {
    sessionManager.clear(); securityLog.log("user_logout");
    setUser(null);
    setPage("home");
  };

  const nav = (p) => setPage(p);

  return (
    <div style={S.app}>
      <Navbar user={user} nav={nav} page={page} logout={logout} />
      <Ticker />
      {toast && <div style={S.toast(toast.type)}>{toast.msg}</div>}
      {modal && <Modal modal={modal} close={() => setModal(null)} />}

      {page === "home" && <HomePage nav={nav} />}
      {page === "login" && <AuthPage mode="login" setUser={setUser} nav={nav} showToast={showToast} />}
      {page === "register" && <AuthPage mode="register" setUser={setUser} nav={nav} showToast={showToast} />}
      {page === "dashboard" && user && <Dashboard user={user} setUser={setUser} showToast={showToast} nav={nav} setModal={setModal} />}
      {page === "admin" && user?.isAdmin && <AdminPanel showToast={showToast} />}
      {!user && page === "dashboard" && <AuthPage mode="login" setUser={setUser} nav={nav} showToast={showToast} />}
    </div>
  );
}

// ── Navbar ───────────────────────────────────────────────────────────────────
function Navbar({ user, nav, page, logout }) {
  return (
    <nav style={S.nav}>
      <div style={S.logo} onClick={() => nav("home")}>⬡ NexVest</div>
      <div style={S.navLinks}>
        {!user ? (
          <>
            <button style={S.navBtn(page === "home")} onClick={() => nav("home")}>Home</button>
            <button style={S.navBtn(page === "login")} onClick={() => nav("login")}>Login</button>
            <button style={{ ...S.btn("primary"), padding: "6px 18px", fontSize: 14 }} onClick={() => nav("register")}>Get Started</button>
          </>
        ) : (
          <>
            <button style={S.navBtn(page === "dashboard")} onClick={() => nav("dashboard")}>Dashboard</button>
            {user.isAdmin && <button style={S.navBtn(page === "admin")} onClick={() => nav("admin")}>Admin</button>}
            <button style={S.navBtn(false)} onClick={logout}>Logout</button>
          </>
        )}
      </div>
    </nav>
  );
}

// ── Ticker ───────────────────────────────────────────────────────────────────
function Ticker() {
  const [pos, setPos] = useState(0);
  const text = TICKERS.join("   •   ");
  useEffect(() => {
    const id = setInterval(() => setPos(p => (p + 1) % (text.length * 8)), 40);
    return () => clearInterval(id);
  }, [text]);
  return (
    <div style={S.ticker}>
      <div style={{ display: "inline-block", transform: `translateX(-${pos}px)`, whiteSpace: "nowrap" }}>
        {text + "   •   " + text}
      </div>
    </div>
  );
}

// ── Home Page ────────────────────────────────────────────────────────────────
function HomePage({ nav }) {
  const [counter, setCounter] = useState(2400000);
  useEffect(() => {
    const id = setInterval(() => setCounter(c => c + Math.floor(Math.random() * 500 + 100)), 1500);
    return () => clearInterval(id);
  }, []);

  return (
    <>
      <div style={S.hero}>
        <div style={{ ...S.badge("#F5C842"), marginBottom: 16 }}>🌍 Trusted by 84,000+ Global Investors</div>
        <h1 style={S.h1}>
          Grow Your Wealth<br /><span style={S.gold}>Without Borders</span>
        </h1>
        <p style={S.sub}>Earn up to 40% ROI with our regulated investment platform. Available in 150+ countries with 13 global payment methods.</p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <button style={S.btn("primary")} onClick={() => nav("register")}>Start Investing →</button>
          <button style={S.btn("secondary")} onClick={() => nav("login")}>View Plans</button>
        </div>
        <div style={{ marginTop: 40, fontSize: 13, color: "#9DAED0" }}>
          Total payouts today: <span style={{ color: "#4ADE80", fontWeight: 700 }}>{fmt(counter)}</span>
        </div>
      </div>

      <div style={{ ...S.page }}>
        {/* Stats */}
        <div style={S.grid3}>
          {[
            { label: "Active Investors", value: "84,321+", icon: "👥" },
            { label: "Total Paid Out", value: "$48.6M+", icon: "💰" },
            { label: "Countries Served", value: "150+", icon: "🌍" },
            { label: "Max ROI", value: "40%", icon: "📈" },
            { label: "Avg. Daily Return", value: "1.4%", icon: "⚡" },
            { label: "Platform Uptime", value: "99.98%", icon: "🛡️" },
          ].map(s => (
            <div key={s.label} style={S.stat}>
              <div style={{ fontSize: 28 }}>{s.icon}</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: "#F5C842", margin: "6px 0 2px" }}>{s.value}</div>
              <div style={{ fontSize: 13, color: "#9DAED0" }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Plans */}
        <h2 style={{ marginTop: 60, marginBottom: 24, fontSize: 28, fontWeight: 800 }}>Investment Plans</h2>
        <div style={S.grid2}>
          {PLANS.map(plan => (
            <div key={plan.id} style={S.planCard(plan.color)}>
              <div style={{ position: "absolute", top: 0, right: 0, width: 80, height: 80, background: plan.color + "11", borderRadius: "0 16px 0 80px" }} />
              <div style={S.badge(plan.color)}>{plan.name}</div>
              <div style={{ fontSize: 32, fontWeight: 900, margin: "12px 0 4px", color: plan.color }}>{plan.roi}% ROI</div>
              <div style={{ color: "#9DAED0", fontSize: 14 }}>in {plan.duration} days</div>
              <div style={{ marginTop: 16, fontSize: 14 }}>
                <div>Min: <strong>{fmt(plan.min)}</strong></div>
                <div>Max: <strong>{plan.max === Infinity ? "Unlimited" : fmt(plan.max)}</strong></div>
              </div>
              <button style={{ ...S.btn("primary"), width: "100%", marginTop: 16 }} onClick={() => nav("register")}>
                Invest Now
              </button>
            </div>
          ))}
        </div>

        {/* Payment Methods */}
        <h2 style={{ marginTop: 60, marginBottom: 8, fontSize: 28, fontWeight: 800 }}>Global Payment Methods</h2>
        <p style={{ color: "#9DAED0", marginBottom: 24 }}>Deposit and withdraw using 13+ methods worldwide</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
          {PAYMENT_METHODS.map(p => (
            <div key={p.id} style={{ ...S.card, margin: 0, display: "flex", alignItems: "center", gap: 10, padding: "10px 16px" }}>
              <span style={{ fontSize: 20, fontWeight: 800, color: "#F5C842" }}>{p.icon}</span>
              <div>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{p.name}</div>
                <div style={{ fontSize: 11, color: "#9DAED0" }}>{p.network}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Referral */}
        <div style={{ marginTop: 60 }}>
          <div style={{ ...S.card, background: "linear-gradient(135deg,#0D1B0D,#111827)", border: "1px solid #4ADE8044", textAlign: "center", padding: "2.5rem 2rem", marginBottom: 16 }}>
            <div style={{ fontSize: 44 }}>🤝</div>
            <h2 style={{ fontSize: 28, fontWeight: 800, margin: "12px 0 8px" }}>Earn on <span style={{ color: "#4ADE80" }}>3 Levels</span> of Referrals</h2>
            <p style={{ color: "#9DAED0", maxWidth: 540, margin: "0 auto 28px", lineHeight: 1.7 }}>
              The most powerful referral program in online investing. Earn commissions not just from who you invite — but from who <em>they</em> invite too.
            </p>
            <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap", marginBottom: 28 }}>
              {[
                { level: "Level 1", rate: "10%", desc: "Direct referrals", color: "#4ADE80" },
                { level: "Level 2", rate: "3%",  desc: "Their referrals",  color: "#60A5FA" },
                { level: "Level 3", rate: "1%",  desc: "3rd generation",   color: "#A78BFA" },
              ].map(lv => (
                <div key={lv.level} style={{ ...S.card, margin: 0, minWidth: 150, textAlign: "center", border: `1px solid ${lv.color}44` }}>
                  <div style={{ fontWeight: 700, color: "#9DAED0", fontSize: 11, marginBottom: 4 }}>{lv.level}</div>
                  <div style={{ fontSize: 36, fontWeight: 900, color: lv.color }}>{lv.rate}</div>
                  <div style={{ fontSize: 12, color: "#9DAED0" }}>{lv.desc}</div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap", marginBottom: 24 }}>
              {[
                { icon: "🥉", label: "Starter", bonus: "$10", target: "1 referral" },
                { icon: "🥈", label: "Connector", bonus: "$50", target: "5 referrals" },
                { icon: "🥇", label: "Influencer", bonus: "$150", target: "10 referrals" },
                { icon: "💎", label: "Ambassador", bonus: "$500", target: "25 referrals" },
                { icon: "👑", label: "Legend", bonus: "$1,500", target: "50 referrals" },
              ].map(b => (
                <div key={b.label} style={{ background: "#0D1427", border: "1px solid #1E2D4A", borderRadius: 10, padding: "10px 16px", textAlign: "center", minWidth: 110 }}>
                  <div style={{ fontSize: 22 }}>{b.icon}</div>
                  <div style={{ fontSize: 13, fontWeight: 700, margin: "4px 0 2px" }}>{b.label}</div>
                  <div style={{ color: "#4ADE80", fontWeight: 800, fontSize: 14 }}>{b.bonus}</div>
                  <div style={{ fontSize: 11, color: "#9DAED0" }}>{b.target}</div>
                </div>
              ))}
            </div>
            <button style={{ ...S.btn("primary"), marginTop: 4 }} onClick={() => nav("register")}>Get My Referral Link →</button>
          </div>
        </div>

        {/* How it works */}
        <h2 style={{ marginTop: 60, marginBottom: 24, fontSize: 28, fontWeight: 800 }}>How It Works</h2>
        <div style={S.grid3}>
          {[
            { n: "01", title: "Create Account", desc: "Sign up in 60 seconds. No KYC delays for most plans." },
            { n: "02", title: "Choose a Plan", desc: "Pick an investment plan that matches your goals and budget." },
            { n: "03", title: "Fund Your Wallet", desc: "Deposit via crypto, bank wire, PayPal, or 10+ other methods." },
            { n: "04", title: "Earn Returns", desc: "Watch your returns grow daily as the platform works for you." },
            { n: "05", title: "Refer Friends", desc: "Share your link and earn multi-level commissions passively." },
            { n: "06", title: "Withdraw Anytime", desc: "Request withdrawals. Processed within 24 hours." },
          ].map(s => (
            <div key={s.n} style={S.card}>
              <div style={{ fontSize: 13, fontWeight: 800, color: "#F5C842", marginBottom: 8 }}>{s.n}</div>
              <div style={{ fontWeight: 700, marginBottom: 4 }}>{s.title}</div>
              <div style={{ fontSize: 14, color: "#9DAED0" }}>{s.desc}</div>
            </div>
          ))}
        </div>

        <footer style={{ textAlign: "center", padding: "3rem 0 1rem", color: "#9DAED0", fontSize: 13, borderTop: "1px solid #1C2538", marginTop: 60 }}>
          <div style={{ fontWeight: 800, color: "#F5C842", fontSize: 20, marginBottom: 8 }}>⬡ NexVest</div>
          <p>© 2025 NexVest Global. All rights reserved. Investment involves risk. Past performance is not indicative of future results.</p>
          <p style={{ marginTop: 8 }}>🌍 Serving 150+ Countries • SSL Secured • 24/7 Support</p>
        </footer>
      </div>
    </>
  );
}

// ── Auth Page ────────────────────────────────────────────────────────────────
function AuthPage({ mode, setUser, nav, showToast }) {
  const [form, setForm] = useState({ name: "", email: "", password: "", refCode: "" });
  const [loading, setLoading] = useState(false);

  const [pwStrength, setPwStrength] = useState(null);

  const onPasswordChange = (val) => {
    setForm({ ...form, password: val });
    if (mode === "register") setPwStrength(checkPasswordStrength(val));
  };

  const submit = async () => {
    // Sanitize inputs
    const email = sanitize(form.email).toLowerCase();
    const name = sanitize(form.name);
    const password = form.password; // don't sanitize password chars

    // Basic validation
    if (!email || !password) return showToast("Please fill all required fields", "error");
    if (!isValidEmail(email)) return showToast("Please enter a valid email address", "error");

    // Check lockout
    const locked = rateLimiter.isLocked(email);
    if (locked) {
      const mins = Math.ceil((locked - Date.now()) / 60000);
      return showToast(`Too many attempts. Try again in ${mins} minute${mins > 1 ? "s" : ""}.`, "error");
    }

    setLoading(true);
    try {
      const data = db.get();

      if (mode === "register") {
        // Password strength check
        const strength = checkPasswordStrength(password);
        if (strength.score < 3) return (setLoading(false), showToast("Password too weak. Use 8+ chars, uppercase, number, and symbol.", "error"));
        if (password.length < 8) return (setLoading(false), showToast("Password must be at least 8 characters", "error"));
        if (data.users[email]) return (setLoading(false), showToast("Email already registered", "error"));

        // Hash password
        const hashedPw = await hashPassword(password);
        const refCode = genRef(name || email);
        const newUser = {
          id: genId(), name, email, password: hashedPw,
          balance: 0, totalInvested: 0, totalEarned: 0,
          referralCode: refCode, referredBy: null,
          joinDate: new Date().toISOString(), isAdmin: false,
          twoFactorEnabled: false, loginCount: 0,
          lastLogin: new Date().toISOString(),
        };

        if (form.refCode) {
          const normalizedCode = sanitize(form.refCode).toUpperCase();
          const referrer = Object.values(data.users).find(u => u.referralCode && u.referralCode.toUpperCase() === normalizedCode);
          if (referrer) {
            newUser.referredBy = referrer.referralCode;
            data.referrals.push({ referrerId: referrer.id, refereeId: newUser.id, refereeEmail: email, date: new Date().toISOString(), status: "active" });
          } else {
            setLoading(false);
            return showToast("Invalid referral code — please check and try again", "error");
          }
        }

        data.users[email] = newUser;
        db.save(data);
        db.save({ users: { ...db.get().users, [email]: newUser } });
        sessionManager.save(newUser);
        securityLog.log("user_register", { email, name });
        setUser(newUser); nav("dashboard");
        showToast("Welcome to NexVest! Account secured 🔐🎉");

      } else {
        // Admin login — hash checked
        const adminHash = await hashPassword("admin123");
        if (email === "admin@nexavest.com" && (password === "admin123" || await hashPassword(password) === adminHash)) {
          const adminUser = { id: "ADMIN", name: "Admin", email, isAdmin: true, balance: 0, totalInvested: 0, totalEarned: 0, referralCode: "ADMIN" };
          sessionManager.save(adminUser);
          securityLog.log("admin_login", { email });
          rateLimiter.reset(email);
          setUser(adminUser); nav("admin");
          showToast("Welcome, Admin! 🛡️");
          setLoading(false);
          return;
        }

        const u = data.users[email];
        if (!u) {
          rateLimiter.increment(email);
          securityLog.log("login_failed", { email, reason: "user_not_found" });
          setLoading(false);
          return showToast("Invalid email or password", "error");
        }

        // Compare hashed password
        const inputHash = await hashPassword(password);
        const storedPw = u.password;
        // Support both hashed and legacy plain (migration)
        const match = (inputHash === storedPw) || (password === storedPw);
        if (!match) {
          const attempt = rateLimiter.increment(email);
          securityLog.log("login_failed", { email, attempts: attempt.attempts });
          const remaining = MAX_ATTEMPTS - attempt.attempts;
          setLoading(false);
          if (remaining <= 0) return showToast(`Account locked for 15 minutes due to too many failed attempts.`, "error");
          return showToast(`Invalid credentials. ${remaining} attempt${remaining !== 1 ? "s" : ""} remaining before lockout.`, "error");
        }

        // If password was stored plain, upgrade to hash
        if (password === storedPw) {
          const d = db.get();
          d.users[email].password = inputHash;
          db.save(d);
        }

        rateLimiter.reset(email);
        const updatedUser = { ...u, lastLogin: new Date().toISOString(), loginCount: (u.loginCount || 0) + 1 };
        const d2 = db.get(); d2.users[email] = updatedUser; db.save(d2);
        sessionManager.save(updatedUser);
        securityLog.log("user_login", { email });
        setUser(updatedUser);
        nav(updatedUser.isAdmin ? "admin" : "dashboard");
        showToast("Welcome back! 👋");
      }
    } catch (err) {
      securityLog.log("auth_error", { error: err.message });
      showToast("An error occurred. Please try again.", "error");
    }
    setLoading(false);
  };

  // Check for referral in URL params (simulated)
  const urlRef = "";

  return (
    <div style={{ ...S.page, maxWidth: 440, paddingTop: "4rem" }}>
      <div style={S.card}>
        <h2 style={{ textAlign: "center", marginBottom: 8, fontSize: 24, fontWeight: 800 }}>
          {mode === "login" ? "Welcome Back" : "Create Account"}
        </h2>
        <SecurityBadges />
        {mode === "register" && (
          <div style={{ marginBottom: 16 }}>
            <label style={S.label}>Full Name</label>
            <input style={S.input} placeholder="John Smith" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          </div>
        )}
        <div style={{ marginBottom: 16 }}>
          <label style={S.label}>Email Address *</label>
          <input style={S.input} type="email" placeholder="you@example.com" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={S.label}>Password *</label>
          <input style={S.input} type="password" placeholder="••••••••" value={form.password} onChange={e => onPasswordChange(e.target.value)} />
          {mode === "register" && <PasswordStrengthMeter password={form.password} />}
        </div>
        {mode === "register" && (
          <div style={{ marginBottom: 20 }}>
            <label style={S.label}>Referral Code (optional)</label>
            <input style={S.input} placeholder="e.g. JOHN1234" value={form.refCode} onChange={e => setForm({ ...form, refCode: e.target.value })} />
          </div>
        )}
        <button style={{ ...S.btn("primary"), width: "100%" }} onClick={submit} disabled={loading}>
          {loading ? "Processing..." : mode === "login" ? "Login" : "Create Account"}
        </button>
        <div style={{ textAlign: "center", marginTop: 16, fontSize: 14, color: "#9DAED0" }}>
          {mode === "login" ? (
            <>No account? <span style={{ color: "#F5C842", cursor: "pointer", fontWeight: 600 }} onClick={() => nav("register")}>Register here</span></>
          ) : (
            <>Have an account? <span style={{ color: "#F5C842", cursor: "pointer", fontWeight: 600 }} onClick={() => nav("login")}>Login</span></>
          )}
        </div>
        {mode === "login" && (
          <div style={{ marginTop: 12, padding: 12, background: "#0D1427", borderRadius: 10, fontSize: 12, color: "#9DAED0", textAlign: "center" }}>
            Admin: admin@nexavest.com / admin123
          </div>
        )}
      </div>
    </div>
  );
}

// ── Dashboard ────────────────────────────────────────────────────────────────
function Dashboard({ user, setUser, showToast, nav, setModal }) {
  const [tab, setTab] = useState("overview");
  const data = db.get();

  // Refresh user from db
  const refreshUser = () => {
    if (!user?.email) return;
    const u = db.get().users[user.email];
    if (u) {
      localStorage.setItem("nexavest_session", JSON.stringify(u));
      setUser(u);
    }
  };

  const tabs = ["overview", "invest", "deposit", "withdraw", "referrals", "history", "support", "notifications"];

  return (
    <div style={S.page}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, margin: 0 }}>Hello, {user.name || user.email.split("@")[0]} 👋</h1>
          <div style={{ color: "#9DAED0", fontSize: 13, marginTop: 4 }}>Referral Code: <span style={{ color: "#F5C842", fontWeight: 700 }}>{user.referralCode}</span></div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {tabs.map(t => {
            const unread = t === "notifications" ? (db.get().notifications || []).filter(n => n.userId === user.id && !n.read).length : 0;
            const icons = { overview: "📊", invest: "📈", deposit: "💰", withdraw: "💸", referrals: "🎁", history: "📜", support: "🎧", notifications: "🔔" };
            return (
              <button key={t} onClick={() => setTab(t)} style={{ ...S.tab(tab === t), position: "relative" }}>
                {icons[t]} {t.charAt(0).toUpperCase() + t.slice(1)}
                {unread > 0 && <span style={{ position: "absolute", top: -4, right: -4, background: "#EF4444", color: "#fff", fontSize: 9, fontWeight: 800, borderRadius: "50%", width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center" }}>{unread}</span>}
              </button>
            );
          })}
        </div>
      </div>

      {tab === "overview" && <OverviewTab user={user} refreshUser={refreshUser} />}
      {tab === "invest" && <InvestTab user={user} refreshUser={refreshUser} showToast={showToast} />}
      {tab === "deposit" && <DepositTab user={user} showToast={showToast} />}
      {tab === "withdraw" && <WithdrawTab user={user} refreshUser={refreshUser} showToast={showToast} />}
      {tab === "referrals" && <ReferralsTab user={user} />}
      {tab === "history" && <HistoryTab user={user} />}
      {tab === "support" && <SupportTab />}
      {tab === "notifications" && <NotificationsTab user={user} refreshUser={refreshUser} />}
    </div>
  );
}

// Overview
function OverviewTab({ user, refreshUser }) {
  const data = db.get();
  const myInvestments = data.investments.filter(i => i.userId === user.id && i.status === "active");

  // Simulate ROI accumulation
  useEffect(() => {
    const id = setInterval(() => {
      const d = db.get();
      let changed = false;
      d.investments.forEach(inv => {
        if (inv.userId === user.id && inv.status === "active") {
          const elapsed = (Date.now() - new Date(inv.startDate).getTime()) / 1000;
          const totalSeconds = inv.duration * 86400;
          if (elapsed >= totalSeconds) {
            const profit = inv.amount * inv.roi / 100;
            d.users[user.email].balance += inv.amount + profit;
            d.users[user.email].totalEarned += profit;
            inv.status = "completed";
            changed = true;
          }
        }
      });
      if (changed) { db.save(d); refreshUser(); }
    }, 5000);
    return () => clearInterval(id);
  }, [user.id]);

  const u = db.get().users[user.email] || user;

  return (
    <>
      <div style={S.grid3}>
        {[
          { label: "Wallet Balance", value: fmt(u.balance || 0), color: "#F5C842" },
          { label: "Total Invested", value: fmt(u.totalInvested || 0), color: "#60A5FA" },
          { label: "Total Earned", value: fmt(u.totalEarned || 0), color: "#4ADE80" },
          { label: "Active Plans", value: myInvestments.length, color: "#A78BFA" },
          { label: "Referrals", value: data.referrals.filter(r => r.referrerId === user.id).length, color: "#F87171" },
          { label: "Member Since", value: new Date(user.joinDate).toLocaleDateString(), color: "#9DAED0" },
        ].map(s => (
          <div key={s.label} style={S.stat}>
            <div style={{ fontSize: 13, color: "#9DAED0" }}>{s.label}</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: s.color, marginTop: 4 }}>{s.value}</div>
          </div>
        ))}
      </div>

      {myInvestments.length > 0 && (
        <>
          <h3 style={{ marginTop: 32, marginBottom: 12 }}>Active Investments</h3>
          {myInvestments.map(inv => {
            const elapsed = (Date.now() - new Date(inv.startDate).getTime()) / (1000 * 86400);
            const progress = Math.min((elapsed / inv.duration) * 100, 100);
            const earned = (inv.amount * inv.roi / 100) * (elapsed / inv.duration);
            return (
              <div key={inv.id} style={S.card}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                  <div>
                    <span style={S.badge(PLANS.find(p => p.name === inv.plan)?.color || "#F5C842")}>{inv.plan}</span>
                    <div style={{ fontWeight: 700, marginTop: 8 }}>{fmt(inv.amount)} invested</div>
                    <div style={{ fontSize: 13, color: "#9DAED0" }}>{inv.roi}% ROI over {inv.duration} days</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 13, color: "#9DAED0" }}>Est. Earned</div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: "#4ADE80" }}>+{fmt(earned)}</div>
                  </div>
                </div>
                <div style={{ marginTop: 12, background: "#0D1427", borderRadius: 8, height: 8 }}>
                  <div style={{ height: "100%", borderRadius: 8, background: "#F5C842", width: `${progress}%`, transition: "width .5s" }} />
                </div>
                <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 4 }}>{progress.toFixed(1)}% complete • {Math.max(0, inv.duration - elapsed).toFixed(0)} days remaining</div>
              </div>
            );
          })}
        </>
      )}

      <div style={{ ...S.card, marginTop: 24, background: "#0D1427", border: "1px solid #4ADE8033" }}>
        <strong style={{ color: "#4ADE80" }}>🔗 Your Referral Link</strong>
        <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
          <input style={{ ...S.input, flex: 1 }} readOnly value={`https://nexvest.com/ref/${user.referralCode}`} />
          <button style={S.btn("sm")} onClick={() => navigator.clipboard?.writeText(`https://nexvest.com/ref/${user.referralCode}`)}>Copy</button>
        </div>
      </div>
    </>
  );
}

// Invest Tab
function InvestTab({ user, refreshUser, showToast }) {
  const [selected, setSelected] = useState(null);
  const [amount, setAmount] = useState("");

  const invest = () => {
    const amt = parseFloat(amount);
    if (!selected) return showToast("Select a plan", "error");
    if (!amt || amt < selected.min) return showToast(`Minimum is ${fmt(selected.min)}`, "error");
    if (amt > selected.max) return showToast(`Maximum is ${fmt(selected.max)}`, "error");
    const u = db.get().users[user.email];
    if ((u?.balance || 0) < amt) return showToast("Insufficient wallet balance. Please deposit first.", "error");

    const d = db.get();
    d.users[user.email].balance -= amt;
    d.users[user.email].totalInvested = (d.users[user.email].totalInvested || 0) + amt;
    d.investments.push({
      id: genId(), userId: user.id, plan: selected.name, amount: amt,
      roi: selected.roi, duration: selected.duration, status: "active",
      startDate: new Date().toISOString(),
    });

    // Multi-level referral commission (L1: 10%, L2: 3%, L3: 1%)
    const REF_LEVELS = [0.10, 0.03, 0.01];
    let currentUser = user;
    for (let level = 0; level < REF_LEVELS.length; level++) {
      if (!currentUser.referredBy) break;
      const referrer = Object.values(d.users).find(u => u.referralCode && currentUser.referredBy && u.referralCode.toUpperCase() === currentUser.referredBy.toUpperCase());
      if (!referrer) break;
      const commission = amt * REF_LEVELS[level];
      d.users[referrer.email].balance = (d.users[referrer.email].balance || 0) + commission;
      d.users[referrer.email].totalReferralEarnings = (d.users[referrer.email].totalReferralEarnings || 0) + commission;
      d.users[referrer.email].totalReferrals = (d.users[referrer.email].totalReferrals || 0);
      d.referrals.push({ referrerId: referrer.id, refereeId: user.id, refereeEmail: user.email, commission, date: new Date().toISOString(), type: "commission", level: level + 1, investmentAmt: amt });
      currentUser = referrer;
    }
    // Track milestone badges
    const allRefs = d.referrals.filter(r => r.referrerId === user.id && r.type !== "commission");
    const directCount = allRefs.length;
    const MILESTONES = [
      { count: 1, badge: "🥉 Starter", bonus: 10 },
      { count: 5, badge: "🥈 Connector", bonus: 50 },
      { count: 10, badge: "🥇 Influencer", bonus: 150 },
      { count: 25, badge: "💎 Ambassador", bonus: 500 },
      { count: 50, badge: "👑 Legend", bonus: 1500 },
    ];
    for (const m of MILESTONES) {
      const alreadyAwarded = (d.users[user.email].milestonesEarned || []).includes(m.badge);
      if (directCount >= m.count && !alreadyAwarded) {
        d.users[user.email].balance = (d.users[user.email].balance || 0) + m.bonus;
        d.users[user.email].milestonesEarned = [...(d.users[user.email].milestonesEarned || []), m.badge];
        d.referrals.push({ referrerId: user.id, refereeId: "SYSTEM", commission: m.bonus, date: new Date().toISOString(), type: "milestone", badge: m.badge });
      }
    }

    db.save(d);
    refreshUser();
    showToast(`Invested ${fmt(amt)} in ${selected.name} plan! 🎉`);
    setAmount(""); setSelected(null);
  };

  return (
    <>
      <h3 style={{ marginBottom: 16 }}>Choose Investment Plan</h3>
      <div style={S.grid2}>
        {PLANS.map(plan => (
          <div key={plan.id}
            style={{ ...S.planCard(plan.color), border: selected?.id === plan.id ? `2px solid ${plan.color}` : `1px solid ${plan.color}40` }}
            onClick={() => { setSelected(plan); setAmount(String(plan.min)); }}
          >
            <div style={S.badge(plan.color)}>{plan.name}</div>
            <div style={{ fontSize: 28, fontWeight: 900, color: plan.color, margin: "10px 0 4px" }}>{plan.roi}% ROI</div>
            <div style={{ color: "#9DAED0", fontSize: 13 }}>in {plan.duration} days</div>
            <div style={{ marginTop: 12, fontSize: 14 }}>
              <div>Min: <strong>{fmt(plan.min)}</strong> | Max: <strong>{plan.max === Infinity ? "∞" : fmt(plan.max)}</strong></div>
            </div>
            {selected?.id === plan.id && <div style={{ marginTop: 8 }}><span style={S.badge(plan.color)}>✓ Selected</span></div>}
          </div>
        ))}
      </div>

      {selected && (
        <div style={{ ...S.card, marginTop: 24 }}>
          <h3 style={{ marginBottom: 16 }}>Invest in {selected.name} Plan</h3>
          <label style={S.label}>Amount (USD)</label>
          <input style={{ ...S.input, marginBottom: 16 }} type="number" value={amount} onChange={e => setAmount(e.target.value)} placeholder={`Min: ${fmt(selected.min)}`} />
          {amount && (
            <div style={{ ...S.card, background: "#0D1427", marginBottom: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", padding: "4px 0" }}>
                <span style={{ color: "#9DAED0" }}>Investment</span><strong>{fmt(parseFloat(amount) || 0)}</strong>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", padding: "4px 0" }}>
                <span style={{ color: "#9DAED0" }}>ROI ({selected.roi}%)</span><strong style={{ color: "#4ADE80" }}>+{fmt((parseFloat(amount) || 0) * selected.roi / 100)}</strong>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderTop: "1px solid #1C2538", marginTop: 8, paddingTop: 8 }}>
                <span style={{ color: "#9DAED0" }}>Total Return</span><strong style={{ color: "#F5C842" }}>{fmt((parseFloat(amount) || 0) * (1 + selected.roi / 100))}</strong>
              </div>
              <div style={{ color: "#9DAED0", fontSize: 12, marginTop: 8 }}>Duration: {selected.duration} days</div>
            </div>
          )}
          <button style={{ ...S.btn("primary"), width: "100%" }} onClick={invest}>Confirm Investment</button>
        </div>
      )}
    </>
  );
}

// Deposit Tab
function DepositTab({ user, showToast }) {
  const [method, setMethod] = useState(null);
  const [amount, setAmount] = useState("");
  const data = db.get();

  const submit = () => {
    if (!method || !amount) return showToast("Select method and enter amount", "error");
    const d = db.get();
    d.withdrawals.push({
      id: genId(), userId: user.id, type: "deposit", method: method.name,
      amount: parseFloat(amount), status: "pending", date: new Date().toISOString(),
    });
    db.save(d);
    showToast("Deposit request submitted! Admin will confirm within 24hrs.");
    setAmount(""); setMethod(null);
  };

  return (
    <>
      <h3 style={{ marginBottom: 16 }}>Fund Your Wallet</h3>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 24 }}>
        {PAYMENT_METHODS.map(p => (
          <button key={p.id}
            style={{ ...S.btn(method?.id === p.id ? "primary" : "secondary"), padding: "8px 14px", fontSize: 13 }}
            onClick={() => setMethod(p)}
          >
            {p.icon} {p.name}
          </button>
        ))}
      </div>

      {method && (
        <div style={S.card}>
          <h4 style={{ marginBottom: 16 }}>Deposit via {method.name}</h4>
          <div style={{ ...S.card, background: "#0D1427", marginBottom: 16 }}>
            <div style={{ fontSize: 13, color: "#9DAED0", marginBottom: 4 }}>Send payment to:</div>
            {data.paymentDetails[method.id]?.address ? (
              <>
                <div style={{ fontFamily: "monospace", fontSize: 15, wordBreak: "break-all", color: "#F5C842", fontWeight: 700 }}>
                  {data.paymentDetails[method.id].address}
                </div>
                {data.paymentDetails[method.id].note && (
                  <div style={{ marginTop: 8, color: "#9DAED0", fontSize: 13 }}>{data.paymentDetails[method.id].note}</div>
                )}
              </>
            ) : (
              <div style={{ color: "#F87171", fontSize: 14 }}>⚠ Payment details not configured. Contact support.</div>
            )}
          </div>
          <label style={S.label}>Amount (USD)</label>
          <input style={{ ...S.input, marginBottom: 16 }} type="number" placeholder="0.00" value={amount} onChange={e => setAmount(e.target.value)} />
          <div style={{ ...S.card, background: "#0D1427", marginBottom: 16, fontSize: 13, color: "#9DAED0" }}>
            ℹ️ Send the exact amount, then submit. Admin will verify and credit your wallet within 24 hours.
          </div>
          <button style={{ ...S.btn("primary"), width: "100%" }} onClick={submit}>I Have Sent — Confirm Deposit</button>
        </div>
      )}
    </>
  );
}

// Withdraw Tab
function WithdrawTab({ user, refreshUser, showToast }) {
  const u = db.get().users[user.email] || user;
  const savedAccounts = u.withdrawalAccounts || [];

  // UI state
  const [section, setSection] = React.useState("withdraw"); // "withdraw" | "accounts"
  const [selectedAccount, setSelectedAccount] = React.useState(null);
  const [amount, setAmount] = React.useState("");

  // Add account form
  const [showAddForm, setShowAddForm] = React.useState(false);
  const [editingId, setEditingId] = React.useState(null);
  const [form, setForm] = React.useState({
    label: "", type: "", address: "",
    bankName: "", accountName: "", accountNumber: "", routingNumber: "", swiftCode: "", iban: "",
    network: "",
  });

  const ACCOUNT_TYPES = [
    { id: "bitcoin",      name: "Bitcoin (BTC)",    icon: "₿",  category: "crypto",  placeholder: "Your BTC wallet address" },
    { id: "ethereum",     name: "Ethereum (ETH)",   icon: "Ξ",  category: "crypto",  placeholder: "Your ETH wallet address" },
    { id: "usdt_trc20",   name: "USDT (TRC-20)",    icon: "₮",  category: "crypto",  placeholder: "Your TRC-20 wallet address" },
    { id: "usdt_erc20",   name: "USDT (ERC-20)",    icon: "₮",  category: "crypto",  placeholder: "Your ERC-20 wallet address" },
    { id: "usdc",         name: "USDC",             icon: "◎",  category: "crypto",  placeholder: "Your USDC wallet address" },
    { id: "bnb",          name: "BNB (BEP-20)",     icon: "🔶", category: "crypto",  placeholder: "Your BEP-20 wallet address" },
    { id: "bank_usd",     name: "Bank Transfer (USD)", icon: "🏦", category: "bank", placeholder: "" },
    { id: "bank_eur",     name: "Bank Transfer (EUR)", icon: "🏦", category: "bank", placeholder: "" },
    { id: "bank_gbp",     name: "Bank Transfer (GBP)", icon: "🏦", category: "bank", placeholder: "" },
    { id: "paypal",       name: "PayPal",           icon: "🅿️", category: "ewallet", placeholder: "Your PayPal email or phone" },
    { id: "skrill",       name: "Skrill",           icon: "💳", category: "ewallet", placeholder: "Your Skrill email" },
    { id: "neteller",     name: "Neteller",         icon: "💳", category: "ewallet", placeholder: "Your Neteller account ID" },
    { id: "perfectmoney", name: "Perfect Money",    icon: "💰", category: "ewallet", placeholder: "Your Perfect Money account ID" },
    { id: "cashapp",      name: "Cash App",         icon: "💵", category: "ewallet", placeholder: "Your $Cashtag" },
    { id: "zelle",        name: "Zelle",            icon: "⚡", category: "ewallet", placeholder: "Your Zelle email or phone" },
  ];

  const selectedType = ACCOUNT_TYPES.find(t => t.id === form.type);
  const isBank = selectedType?.category === "bank";
  const isCrypto = selectedType?.category === "crypto";
  const isEwallet = selectedType?.category === "ewallet";

  const resetForm = () => {
    setForm({ label: "", type: "", address: "", bankName: "", accountName: "", accountNumber: "", routingNumber: "", swiftCode: "", iban: "", network: "" });
    setEditingId(null);
    setShowAddForm(false);
  };

  const startEdit = (acc) => {
    setForm({ ...acc });
    setEditingId(acc.id);
    setShowAddForm(true);
    setSection("accounts");
  };

  const saveAccount = () => {
    if (!form.type || !form.label) return showToast("Please fill in all required fields", "error");
    if (isCrypto && !form.address) return showToast("Wallet address is required", "error");
    if (isBank && (!form.bankName || !form.accountName || !form.accountNumber)) return showToast("Please fill all bank details", "error");
    if (isEwallet && !form.address) return showToast("Account details are required", "error");

    const d = db.get();
    const accs = d.users[user.email].withdrawalAccounts || [];

    if (editingId) {
      const idx = accs.findIndex(a => a.id === editingId);
      if (idx >= 0) accs[idx] = { ...form, id: editingId };
    } else {
      accs.push({ ...form, id: genId(), addedDate: new Date().toISOString() });
    }

    d.users[user.email].withdrawalAccounts = accs;
    db.save(d);
    refreshUser();
    showToast(editingId ? "Account updated!" : "Account saved successfully!");
    resetForm();
  };

  const deleteAccount = (id) => {
    const d = db.get();
    d.users[user.email].withdrawalAccounts = (d.users[user.email].withdrawalAccounts || []).filter(a => a.id !== id);
    db.save(d);
    refreshUser();
    if (selectedAccount?.id === id) setSelectedAccount(null);
    showToast("Account removed");
  };

  const submitWithdrawal = () => {
    const amt = parseFloat(amount);
    if (!selectedAccount) return showToast("Please select a withdrawal account", "error");
    if (!amt || amt < 10) return showToast("Minimum withdrawal is $10", "error");
    if (amt > (u.balance || 0)) return showToast("Insufficient balance", "error");

    const d = db.get();
    d.users[user.email].balance = (d.users[user.email].balance || 0) - amt;
    d.withdrawals.push({
      id: genId(), userId: user.id, type: "withdrawal",
      method: selectedAccount.label,
      accountType: selectedAccount.type,
      accountDetails: selectedAccount,
      amount: amt, status: "pending",
      date: new Date().toISOString(),
    });
    db.save(d);
    refreshUser();
    showToast("Withdrawal request submitted! Processing within 24 hours.");
    setAmount("");
    setSelectedAccount(null);
  };

  const typeColor = (cat) => cat === "crypto" ? "#F59E0B" : cat === "bank" ? "#60A5FA" : "#4ADE80";
  const typeIcon = (cat) => cat === "crypto" ? "🔐" : cat === "bank" ? "🏦" : "💳";

  const freshU = db.get().users[user.email] || user;
  const freshAccounts = freshU.withdrawalAccounts || [];

  return (
    <div style={{ maxWidth: 720 }}>
      {/* Balance banner */}
      <div style={{ background: "linear-gradient(135deg,#0D1B2A,#111827)", border: "1px solid #1E2D4A", borderRadius: 14, padding: "20px 24px", marginBottom: 24, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 12, color: "#9DAED0", fontWeight: 600, marginBottom: 4 }}>AVAILABLE BALANCE</div>
          <div style={{ fontSize: 36, fontWeight: 900, color: "#F5C842" }}>{fmt(freshU.balance || 0)}</div>
          <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 4 }}>Min withdrawal: $10 · Processed within 24hrs</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 12, color: "#9DAED0" }}>Saved Accounts</div>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#60A5FA" }}>{freshAccounts.length}</div>
        </div>
      </div>

      {/* Section tabs */}
      <div style={{ display: "flex", gap: 4, background: "#0D1427", borderRadius: 10, padding: 4, marginBottom: 24 }}>
        {[["withdraw","💸 Withdraw"],["accounts","🏦 My Accounts"]].map(([s, label]) => (
          <button key={s} onClick={() => setSection(s)} style={{
            flex: 1, padding: "10px", borderRadius: 8, border: "none", cursor: "pointer", fontWeight: 700, fontSize: 14, fontFamily: "inherit",
            background: section === s ? "#1A56DB" : "transparent",
            color: section === s ? "#fff" : "#9DAED0",
          }}>{label}</button>
        ))}
      </div>

      {/* ── WITHDRAW SECTION ── */}
      {section === "withdraw" && (
        <>
          {freshAccounts.length === 0 ? (
            <div style={{ ...S.card, textAlign: "center", padding: "3rem 2rem" }}>
              <div style={{ fontSize: 52, marginBottom: 16 }}>🏦</div>
              <div style={{ fontWeight: 700, fontSize: 18, marginBottom: 8 }}>No Withdrawal Accounts Yet</div>
              <div style={{ color: "#9DAED0", fontSize: 14, marginBottom: 24, lineHeight: 1.6 }}>
                Add your crypto wallet, bank account, or e-wallet details first so we know where to send your money.
              </div>
              <button style={S.btn("primary")} onClick={() => { setSection("accounts"); setShowAddForm(true); }}>
                + Add Withdrawal Account
              </button>
            </div>
          ) : (
            <>
              {/* Account picker */}
              <div style={{ ...S.card, marginBottom: 16 }}>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 16 }}>1. Select Withdrawal Account</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {freshAccounts.map(acc => {
                    const t = ACCOUNT_TYPES.find(x => x.id === acc.type);
                    const cat = t?.category || "crypto";
                    const isSelected = selectedAccount?.id === acc.id;
                    return (
                      <div key={acc.id} onClick={() => setSelectedAccount(isSelected ? null : acc)}
                        style={{ display: "flex", alignItems: "center", gap: 14, padding: "14px 16px", borderRadius: 12, cursor: "pointer", border: isSelected ? "2px solid #1A56DB" : "1px solid #1E2D4A", background: isSelected ? "rgba(26,86,219,0.08)" : "#0D1427", transition: "all 0.15s" }}>
                        <div style={{ width: 42, height: 42, borderRadius: 10, background: `${typeColor(cat)}18`, border: `1px solid ${typeColor(cat)}33`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0 }}>
                          {t?.icon || "💳"}
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontWeight: 700, fontSize: 14 }}>{acc.label}</div>
                          <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 2 }}>
                            {t?.name || acc.type}
                            {cat === "crypto" && acc.address && ` · ${acc.address.slice(0,8)}...${acc.address.slice(-6)}`}
                            {cat === "bank" && acc.accountNumber && ` · ****${acc.accountNumber.slice(-4)}`}
                            {cat === "ewallet" && acc.address && ` · ${acc.address}`}
                          </div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ background: `${typeColor(cat)}22`, color: typeColor(cat), fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 20 }}>{cat.toUpperCase()}</span>
                          {isSelected && <span style={{ color: "#1A56DB", fontSize: 20, fontWeight: 800 }}>✓</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
                <button style={{ ...S.btn("ghost"), width: "100%", marginTop: 12, fontSize: 13 }} onClick={() => { setSection("accounts"); setShowAddForm(true); }}>
                  + Add New Account
                </button>
              </div>

              {/* Amount input */}
              <div style={{ ...S.card, marginBottom: 16 }}>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 16 }}>2. Enter Amount</div>
                <div style={{ position: "relative" }}>
                  <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", color: "#9DAED0", fontWeight: 700, fontSize: 16 }}>$</span>
                  <input style={{ ...S.input, paddingLeft: 28, fontSize: 22, fontWeight: 700 }} type="number" placeholder="0.00" min="10" max={freshU.balance || 0} value={amount} onChange={e => setAmount(e.target.value)} />
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                  {[25, 50, 75, 100].map(pct => (
                    <button key={pct} style={{ ...S.btn("ghost"), flex: 1, fontSize: 12, padding: "6px 4px" }}
                      onClick={() => setAmount(((freshU.balance || 0) * pct / 100).toFixed(2))}>
                      {pct}%
                    </button>
                  ))}
                </div>
                {amount && parseFloat(amount) >= 10 && (
                  <div style={{ marginTop: 14, background: "#0D1427", borderRadius: 10, padding: "12px 16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 6 }}>
                      <span style={{ color: "#9DAED0" }}>Amount</span>
                      <span>{fmt(parseFloat(amount))}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 6 }}>
                      <span style={{ color: "#9DAED0" }}>Processing fee (1.5%)</span>
                      <span style={{ color: "#F87171" }}>-{fmt(parseFloat(amount) * 0.015)}</span>
                    </div>
                    <div style={{ borderTop: "1px solid #1E2D4A", paddingTop: 8, marginTop: 4, display: "flex", justifyContent: "space-between", fontWeight: 700 }}>
                      <span>You receive</span>
                      <span style={{ color: "#4ADE80", fontSize: 16 }}>{fmt(parseFloat(amount) * 0.985)}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Summary + submit */}
              {selectedAccount && amount && parseFloat(amount) >= 10 && (
                <div style={{ ...S.card, background: "linear-gradient(135deg,#0D200D,#111827)", border: "1px solid #4ADE8044", marginBottom: 16 }}>
                  <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 14 }}>3. Confirm Withdrawal</div>
                  {[
                    ["Amount", fmt(parseFloat(amount))],
                    ["You receive", fmt(parseFloat(amount) * 0.985)],
                    ["To", selectedAccount.label],
                    ["Method", ACCOUNT_TYPES.find(t => t.id === selectedAccount.type)?.name || selectedAccount.type],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 14, marginBottom: 8 }}>
                      <span style={{ color: "#9DAED0" }}>{k}</span>
                      <span style={{ fontWeight: 600 }}>{v}</span>
                    </div>
                  ))}
                </div>
              )}

              <button style={{ ...S.btn("primary"), width: "100%", padding: "14px", fontSize: 15, fontWeight: 800 }}
                disabled={!selectedAccount || !amount || parseFloat(amount) < 10 || parseFloat(amount) > (freshU.balance || 0)}
                onClick={submitWithdrawal}>
                💸 Submit Withdrawal Request
              </button>
            </>
          )}
        </>
      )}

      {/* ── MY ACCOUNTS SECTION ── */}
      {section === "accounts" && (
        <>
          {/* Saved accounts list */}
          {!showAddForm && (
            <>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                <div style={{ fontWeight: 700, fontSize: 16 }}>Saved Withdrawal Accounts</div>
                <button style={S.btn("primary")} onClick={() => setShowAddForm(true)}>+ Add Account</button>
              </div>

              {freshAccounts.length === 0 ? (
                <div style={{ ...S.card, textAlign: "center", padding: "3rem 2rem" }}>
                  <div style={{ fontSize: 52, marginBottom: 16 }}>🏦</div>
                  <div style={{ fontWeight: 700, marginBottom: 8 }}>No Accounts Added Yet</div>
                  <div style={{ color: "#9DAED0", fontSize: 14, marginBottom: 20 }}>Add your crypto wallet, bank, or e-wallet to start withdrawing.</div>
                  <button style={S.btn("primary")} onClick={() => setShowAddForm(true)}>+ Add Your First Account</button>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {freshAccounts.map(acc => {
                    const t = ACCOUNT_TYPES.find(x => x.id === acc.type);
                    const cat = t?.category || "crypto";
                    return (
                      <div key={acc.id} style={{ background: "#111827", border: "1px solid #1E2D4A", borderRadius: 14, padding: "18px 20px" }}>
                        <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
                          <div style={{ width: 46, height: 46, borderRadius: 12, background: `${typeColor(cat)}18`, border: `1px solid ${typeColor(cat)}33`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, flexShrink: 0 }}>
                            {t?.icon || "💳"}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8, marginBottom: 8 }}>
                              <div>
                                <div style={{ fontWeight: 700, fontSize: 15 }}>{acc.label}</div>
                                <div style={{ fontSize: 12, color: typeColor(cat), fontWeight: 600, marginTop: 2 }}>{t?.name || acc.type}</div>
                              </div>
                              <div style={{ display: "flex", gap: 8 }}>
                                <button style={{ ...S.btn("ghost"), padding: "5px 12px", fontSize: 12 }} onClick={() => startEdit(acc)}>✏️ Edit</button>
                                <button style={{ ...S.btn("danger"), padding: "5px 12px", fontSize: 12 }} onClick={() => deleteAccount(acc.id)}>🗑</button>
                              </div>
                            </div>
                            {/* Show details based on type */}
                            <div style={{ background: "#0D1427", borderRadius: 8, padding: "10px 14px", fontSize: 13 }}>
                              {cat === "crypto" && (
                                <div>
                                  <span style={{ color: "#9DAED0" }}>Address: </span>
                                  <span style={{ fontFamily: "monospace", color: "#F1F5F9", wordBreak: "break-all" }}>{acc.address}</span>
                                  {acc.network && <div style={{ color: "#9DAED0", marginTop: 4 }}>Network: <span style={{ color: "#F1F5F9" }}>{acc.network}</span></div>}
                                </div>
                              )}
                              {cat === "bank" && (
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 16px" }}>
                                  {[["Bank", acc.bankName], ["Account Name", acc.accountName], ["Account No.", `****${acc.accountNumber?.slice(-4)}`], acc.routingNumber && ["Routing No.", acc.routingNumber], acc.swiftCode && ["SWIFT", acc.swiftCode], acc.iban && ["IBAN", acc.iban]].filter(Boolean).map(([k, v]) => (
                                    <div key={k}><span style={{ color: "#9DAED0" }}>{k}: </span><span>{v}</span></div>
                                  ))}
                                </div>
                              )}
                              {cat === "ewallet" && (
                                <div><span style={{ color: "#9DAED0" }}>Account: </span><span>{acc.address}</span></div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}

          {/* Add / Edit form */}
          {showAddForm && (
            <div style={{ ...S.card }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                <div style={{ fontWeight: 700, fontSize: 17 }}>{editingId ? "Edit Account" : "Add Withdrawal Account"}</div>
                <button style={{ ...S.btn("ghost"), padding: "4px 12px", fontSize: 12 }} onClick={resetForm}>✕ Cancel</button>
              </div>

              {/* Account label */}
              <div style={{ marginBottom: 14 }}>
                <label style={S.label}>Account Label (your nickname for this account) *</label>
                <input style={S.input} placeholder='e.g. "My BTC Wallet", "Business Bank Account"' value={form.label} onChange={e => setForm({ ...form, label: e.target.value })} />
              </div>

              {/* Account type */}
              <div style={{ marginBottom: 16 }}>
                <label style={S.label}>Account Type *</label>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px,1fr))", gap: 8 }}>
                  {["crypto","bank","ewallet"].map(cat => (
                    <div key={cat}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: typeColor(cat), textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>{typeIcon(cat)} {cat}</div>
                      {ACCOUNT_TYPES.filter(t => t.category === cat).map(t => (
                        <button key={t.id} onClick={() => setForm({ ...form, type: t.id })}
                          style={{ display: "block", width: "100%", textAlign: "left", padding: "8px 12px", borderRadius: 8, border: form.type === t.id ? `2px solid ${typeColor(cat)}` : "1px solid #1E2D4A", background: form.type === t.id ? `${typeColor(cat)}18` : "#0D1427", color: form.type === t.id ? "#F1F5F9" : "#9DAED0", fontWeight: form.type === t.id ? 700 : 400, fontSize: 13, cursor: "pointer", marginBottom: 6, fontFamily: "inherit" }}>
                          {t.icon} {t.name}
                        </button>
                      ))}
                    </div>
                  ))}
                </div>
              </div>

              {/* Crypto fields */}
              {isCrypto && (
                <>
                  <div style={{ marginBottom: 14 }}>
                    <label style={S.label}>Wallet Address *</label>
                    <input style={S.input} placeholder={selectedType?.placeholder || "Your wallet address"} value={form.address} onChange={e => setForm({ ...form, address: e.target.value })} />
                  </div>
                  <div style={{ marginBottom: 14 }}>
                    <label style={S.label}>Network (optional)</label>
                    <input style={S.input} placeholder='e.g. "Mainnet", "BSC", "Polygon"' value={form.network} onChange={e => setForm({ ...form, network: e.target.value })} />
                  </div>
                </>
              )}

              {/* Bank fields */}
              {isBank && (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
                    <div>
                      <label style={S.label}>Bank Name *</label>
                      <input style={S.input} placeholder="e.g. Chase, Barclays" value={form.bankName} onChange={e => setForm({ ...form, bankName: e.target.value })} />
                    </div>
                    <div>
                      <label style={S.label}>Account Holder Name *</label>
                      <input style={S.input} placeholder="Full name on account" value={form.accountName} onChange={e => setForm({ ...form, accountName: e.target.value })} />
                    </div>
                  </div>
                  <div style={{ marginBottom: 14 }}>
                    <label style={S.label}>Account Number *</label>
                    <input style={S.input} placeholder="Your bank account number" value={form.accountNumber} onChange={e => setForm({ ...form, accountNumber: e.target.value })} />
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
                    <div>
                      <label style={S.label}>Routing Number (US)</label>
                      <input style={S.input} placeholder="9-digit routing number" value={form.routingNumber} onChange={e => setForm({ ...form, routingNumber: e.target.value })} />
                    </div>
                    <div>
                      <label style={S.label}>SWIFT / BIC Code</label>
                      <input style={S.input} placeholder="e.g. CHASUS33" value={form.swiftCode} onChange={e => setForm({ ...form, swiftCode: e.target.value })} />
                    </div>
                  </div>
                  <div style={{ marginBottom: 14 }}>
                    <label style={S.label}>IBAN (International)</label>
                    <input style={S.input} placeholder="e.g. GB29 NWBK 6016 1331 9268 19" value={form.iban} onChange={e => setForm({ ...form, iban: e.target.value })} />
                  </div>
                </>
              )}

              {/* E-wallet fields */}
              {isEwallet && (
                <div style={{ marginBottom: 14 }}>
                  <label style={S.label}>Account Email / ID / Username *</label>
                  <input style={S.input} placeholder={selectedType?.placeholder || "Your account identifier"} value={form.address} onChange={e => setForm({ ...form, address: e.target.value })} />
                </div>
              )}

              {selectedType && (
                <div style={{ background: "#0D1A0D", border: "1px solid #4ADE8033", borderRadius: 8, padding: "10px 14px", marginBottom: 16, fontSize: 13, color: "#9DAED0" }}>
                  🔒 Your account details are encrypted and stored securely. They are only used for processing your withdrawal requests.
                </div>
              )}

              <button style={{ ...S.btn("primary"), width: "100%", padding: "13px" }}
                disabled={!form.type || !form.label}
                onClick={saveAccount}>
                {editingId ? "💾 Update Account" : "💾 Save Account"}
              </button>
            </div>
          )}
        </>
      )}

      {/* Withdrawal history */}
      <div style={{ ...S.card, marginTop: 24 }}>
        <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 16 }}>Withdrawal History</div>
        {(() => {
          const history = (db.get().withdrawals || []).filter(w => w.userId === user.id).sort((a,b) => new Date(b.date) - new Date(a.date));
          if (!history.length) return <div style={{ textAlign: "center", color: "#9DAED0", padding: "1.5rem", fontSize: 14 }}>No withdrawals yet</div>;
          return (
            <div style={{ overflowX: "auto" }}>
              <table style={S.table}>
                <thead><tr>
                  <th style={S.th}>Account</th><th style={S.th}>Amount</th><th style={S.th}>You Receive</th><th style={S.th}>Status</th><th style={S.th}>Date</th>
                </tr></thead>
                <tbody>
                  {history.map(w => (
                    <tr key={w.id}>
                      <td style={S.td}><div style={{ fontWeight: 600 }}>{w.method}</div><div style={{ fontSize: 11, color: "#9DAED0" }}>{w.accountType}</div></td>
                      <td style={{ ...S.td, color: "#F87171", fontWeight: 700 }}>-{fmt(w.amount)}</td>
                      <td style={{ ...S.td, color: "#4ADE80", fontWeight: 700 }}>{fmt(w.amount * 0.985)}</td>
                      <td style={S.td}><span style={{ background: w.status === "completed" ? "#4ADE8022" : w.status === "pending" ? "#F5C84222" : "#F8717122", color: w.status === "completed" ? "#4ADE80" : w.status === "pending" ? "#F5C842" : "#F87171", padding: "3px 10px", borderRadius: 20, fontSize: 12, fontWeight: 700 }}>{w.status}</span></td>
                      <td style={{ ...S.td, color: "#9DAED0", fontSize: 12 }}>{new Date(w.date).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

// Referrals Tab
function ReferralsTab({ user }) {
  const data = db.get();
  const allRefs = data.referrals.filter(r => r.referrerId === user.id);
  const directRefs = allRefs.filter(r => r.status === "active" && r.type !== "commission" && r.type !== "milestone");
  const commissions = allRefs.filter(r => r.type === "commission");
  const milestones = allRefs.filter(r => r.type === "milestone");
  const totalCommission = commissions.reduce((s, r) => s + (r.commission || 0), 0);
  const totalMilestone = milestones.reduce((s, r) => s + (r.commission || 0), 0);
  const totalEarned = totalCommission + totalMilestone;
  const l1 = commissions.filter(r => r.level === 1);
  const l2 = commissions.filter(r => r.level === 2);
  const l3 = commissions.filter(r => r.level === 3);
  const [tab, setTab] = React.useState("overview");
  const [copied, setCopied] = React.useState(false);
  const refLink = `https://nexvest.com/ref/${user.referralCode}`;

  const copyLink = () => {
    navigator.clipboard?.writeText(refLink);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const MILESTONES = [
    { count: 1,  badge: "🥉 Starter",    bonus: 10,   label: "First referral" },
    { count: 5,  badge: "🥈 Connector",  bonus: 50,   label: "5 referrals" },
    { count: 10, badge: "🥇 Influencer", bonus: 150,  label: "10 referrals" },
    { count: 25, badge: "💎 Ambassador", bonus: 500,  label: "25 referrals" },
    { count: 50, badge: "👑 Legend",     bonus: 1500, label: "50 referrals" },
  ];
  const earnedBadges = user.milestonesEarned || [];
  const nextMilestone = MILESTONES.find(m => directRefs.length < m.count);
  const progressToNext = nextMilestone ? (directRefs.length / nextMilestone.count) * 100 : 100;

  // Build leaderboard from all users (simulate)
  const allUsers = Object.values(data.users);
  const leaderboard = allUsers
    .map(u => ({
      name: u.name || u.email,
      refs: data.referrals.filter(r => r.referrerId === u.id && r.status === "active" && r.type !== "commission" && r.type !== "milestone").length,
      earned: data.referrals.filter(r => r.referrerId === u.id).reduce((s, r) => s + (r.commission || 0), 0),
    }))
    .filter(u => u.refs > 0)
    .sort((a, b) => b.refs - a.refs)
    .slice(0, 10);

  const tabStyle = (t) => ({
    padding: "8px 18px", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 600,
    background: tab === t ? "#F5C842" : "transparent",
    color: tab === t ? "#0A0F1E" : "#9DAED0",
    border: "none", fontFamily: "inherit",
  });

  return (
    <>
      {/* Header stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Direct Referrals", value: directRefs.length, icon: "👥", color: "#60A5FA" },
          { label: "Total Earned", value: fmt(totalEarned), icon: "💰", color: "#4ADE80" },
          { label: "L1 Commission", value: fmt(l1.reduce((s,r)=>s+(r.commission||0),0)), icon: "⚡", color: "#F5C842" },
          { label: "L2+L3 Earned", value: fmt(l2.concat(l3).reduce((s,r)=>s+(r.commission||0),0)), icon: "🔗", color: "#A78BFA" },
          { label: "Milestone Bonuses", value: fmt(totalMilestone), icon: "🏆", color: "#FB923C" },
          { label: "Badges Earned", value: earnedBadges.length, icon: "🎖️", color: "#F472B6" },
        ].map(s => (
          <div key={s.label} style={{ background: "#111827", borderRadius: 12, padding: "16px 14px", border: "1px solid #1E2D4A" }}>
            <div style={{ fontSize: 22 }}>{s.icon}</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: s.color, margin: "6px 0 2px" }}>{s.value}</div>
            <div style={{ fontSize: 11, color: "#9DAED0" }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tab navigation */}
      <div style={{ display: "flex", gap: 4, background: "#0D1427", borderRadius: 10, padding: 4, marginBottom: 20, flexWrap: "wrap" }}>
        {[["overview","📊 Overview"],["share","🔗 Share"],["milestones","🏆 Milestones"],["earnings","💰 Earnings"],["leaderboard","🥇 Leaderboard"]].map(([t, label]) => (
          <button key={t} style={tabStyle(t)} onClick={() => setTab(t)}>{label}</button>
        ))}
      </div>

      {/* OVERVIEW */}
      {tab === "overview" && (
        <>
          {/* Multi-level diagram */}
          <div style={{ ...S.card, background: "linear-gradient(135deg,#0D1B0D,#111827)", border: "1px solid #4ADE8033", marginBottom: 16, textAlign: "center" }}>
            <h3 style={{ marginBottom: 6 }}>🌳 Multi-Level Commission Structure</h3>
            <p style={{ color: "#9DAED0", fontSize: 13, marginBottom: 24 }}>Earn on 3 levels — your referrals, their referrals, and theirs too</p>
            <div style={{ display: "flex", justifyContent: "center", gap: 0, alignItems: "stretch", flexWrap: "wrap" }}>
              {[
                { level: "Level 1", rate: "10%", desc: "People you invite", color: "#4ADE80", bg: "#0D2010" },
                { level: "Level 2", rate: "3%",  desc: "Their invitees",   color: "#60A5FA", bg: "#0D1520" },
                { level: "Level 3", rate: "1%",  desc: "3rd generation",   color: "#A78BFA", bg: "#150D20" },
              ].map((lv, i) => (
                <div key={lv.level} style={{ flex: 1, minWidth: 140, padding: "20px 16px", background: lv.bg, border: `1px solid ${lv.color}33`, borderRadius: i === 0 ? "12px 0 0 12px" : i === 2 ? "0 12px 12px 0" : "0", position: "relative" }}>
                  {i < 2 && <div style={{ position: "absolute", right: -12, top: "50%", transform: "translateY(-50%)", color: "#9DAED0", fontSize: 18, zIndex: 1 }}>→</div>}
                  <div style={{ fontSize: 12, color: "#9DAED0", fontWeight: 600, marginBottom: 8 }}>{lv.level}</div>
                  <div style={{ fontSize: 40, fontWeight: 900, color: lv.color }}>{lv.rate}</div>
                  <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 4 }}>{lv.desc}</div>
                  <div style={{ fontSize: 11, color: lv.color, marginTop: 8, fontWeight: 600 }}>
                    {lv.level === "Level 1" ? `${l1.length} payouts` : lv.level === "Level 2" ? `${l2.length} payouts` : `${l3.length} payouts`}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Progress to next milestone */}
          {nextMilestone && (
            <div style={{ ...S.card, marginBottom: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <span style={{ fontWeight: 600 }}>Progress to {nextMilestone.badge}</span>
                <span style={{ color: "#9DAED0", fontSize: 13 }}>{directRefs.length} / {nextMilestone.count} referrals</span>
              </div>
              <div style={{ height: 10, background: "#1E2D4A", borderRadius: 5, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${progressToNext}%`, background: "linear-gradient(90deg,#4ADE80,#22D3EE)", borderRadius: 5, transition: "width 0.5s" }} />
              </div>
              <div style={{ marginTop: 8, fontSize: 13, color: "#9DAED0" }}>
                {nextMilestone.count - directRefs.length} more referrals to unlock <span style={{ color: "#F5C842", fontWeight: 700 }}>{nextMilestone.badge}</span> + <span style={{ color: "#4ADE80", fontWeight: 700 }}>{fmt(nextMilestone.bonus)} bonus</span>
              </div>
            </div>
          )}

          {/* Example earnings calculator */}
          <div style={{ ...S.card }}>
            <h4 style={{ marginBottom: 16 }}>💡 Earnings Potential Calculator</h4>
            <div style={{ overflowX: "auto" }}>
              <table style={S.table}>
                <thead>
                  <tr>
                    <th style={S.th}>Referrals</th>
                    <th style={S.th}>Avg. Investment</th>
                    <th style={S.th}>L1 (10%)</th>
                    <th style={S.th}>L2 (3%)</th>
                    <th style={S.th}>L3 (1%)</th>
                    <th style={S.th}>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {[[5,1000],[10,1000],[25,2000],[50,5000]].map(([refs, avg]) => {
                    const l1e = refs * avg * 0.10;
                    const l2e = refs * 3 * avg * 0.03;
                    const l3e = refs * 3 * 3 * avg * 0.01;
                    return (
                      <tr key={refs}>
                        <td style={S.td}>{refs}</td>
                        <td style={S.td}>{fmt(avg)}</td>
                        <td style={{ ...S.td, color: "#4ADE80", fontWeight: 700 }}>{fmt(l1e)}</td>
                        <td style={{ ...S.td, color: "#60A5FA" }}>{fmt(l2e)}</td>
                        <td style={{ ...S.td, color: "#A78BFA" }}>{fmt(l3e)}</td>
                        <td style={{ ...S.td, color: "#F5C842", fontWeight: 800 }}>{fmt(l1e+l2e+l3e)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* SHARE */}
      {tab === "share" && (
        <div style={{ maxWidth: 600 }}>
          <div style={{ ...S.card, marginBottom: 16 }}>
            <h4 style={{ marginBottom: 4 }}>🔗 Your Referral Link</h4>
            <p style={{ color: "#9DAED0", fontSize: 13, marginBottom: 14 }}>Share this link. When someone registers and invests, you earn automatically.</p>
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <input style={{ ...S.input, flex: 1, fontFamily: "monospace", fontSize: 13 }} readOnly value={refLink} />
              <button style={S.btn(copied ? "success" : "primary")} onClick={copyLink}>{copied ? "✓ Copied!" : "Copy"}</button>
            </div>
            <div style={{ background: "#0D1427", borderRadius: 8, padding: "10px 16px", textAlign: "center", marginBottom: 12 }}>
              <span style={{ color: "#9DAED0", fontSize: 12 }}>Your Code: </span>
              <span style={{ color: "#F5C842", fontWeight: 800, fontSize: 20, letterSpacing: 3, fontFamily: "monospace" }}>{user.referralCode}</span>
            </div>
          </div>

          <div style={{ ...S.card, marginBottom: 16 }}>
            <h4 style={{ marginBottom: 14 }}>📣 Share Directly</h4>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              {[
                { label: "📱 WhatsApp", url: `https://wa.me/?text=Join NexVest and start earning! Use my link: ${refLink}`, color: "#25D366" },
                { label: "✈️ Telegram", url: `https://t.me/share/url?url=${refLink}&text=Join NexVest and earn up to 40% ROI!`, color: "#0088CC" },
                { label: "🐦 Twitter", url: `https://twitter.com/intent/tweet?text=I%27m earning great returns on NexVest. Join me: ${refLink}`, color: "#1DA1F2" },
                { label: "📘 Facebook", url: `https://www.facebook.com/sharer/sharer.php?u=${refLink}`, color: "#1877F2" },
                { label: "💼 LinkedIn", url: `https://www.linkedin.com/sharing/share-offsite/?url=${refLink}`, color: "#0A66C2" },
                { label: "✉️ Email", url: `mailto:?subject=Join NexVest&body=Hey! I'm using NexVest for investments. Join here: ${refLink}`, color: "#EA4335" },
              ].map(s => (
                <a key={s.label} href={s.url} target="_blank" rel="noopener noreferrer"
                  style={{ padding: "12px", background: "#111827", border: `1px solid ${s.color}44`, borderRadius: 10, textDecoration: "none", color: "#F1F5F9", fontSize: 14, fontWeight: 600, textAlign: "center", display: "block" }}>
                  {s.label}
                </a>
              ))}
            </div>
          </div>

          <div style={{ ...S.card }}>
            <h4 style={{ marginBottom: 14 }}>📝 Ready-Made Messages</h4>
            {[
              { label: "Casual", msg: `Hey! I've been using NexVest for investing and the returns are great. You should try it — use my link to get started: ${refLink}` },
              { label: "Professional", msg: `I wanted to share an investment platform I've been using — NexVest. They offer up to 40% ROI with multiple payment options. Sign up with my referral: ${refLink}` },
            ].map(m => (
              <div key={m.label} style={{ background: "#0D1427", borderRadius: 8, padding: 14, marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: "#9DAED0" }}>{m.label}</span>
                  <button style={{ ...S.btn("sm"), padding: "3px 10px", fontSize: 11 }} onClick={() => navigator.clipboard?.writeText(m.msg)}>Copy</button>
                </div>
                <p style={{ fontSize: 13, color: "#CBD5E1", lineHeight: 1.6, margin: 0 }}>{m.msg}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MILESTONES */}
      {tab === "milestones" && (
        <>
          <div style={{ ...S.card, marginBottom: 16, background: "linear-gradient(135deg,#1a1500,#111827)", border: "1px solid #F5C84233" }}>
            <h3 style={{ marginBottom: 4 }}>🏆 Achievement Milestones</h3>
            <p style={{ color: "#9DAED0", fontSize: 13, marginBottom: 0 }}>Reach referral targets to unlock bonus rewards and exclusive badges</p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {MILESTONES.map((m, i) => {
              const earned = earnedBadges.includes(m.badge);
              const current = nextMilestone?.badge === m.badge;
              const pct = Math.min(100, (directRefs.length / m.count) * 100);
              return (
                <div key={m.badge} style={{ ...S.card, border: earned ? "1px solid #4ADE8066" : current ? "1px solid #F5C84266" : "1px solid #1E2D4A", background: earned ? "#0D2010" : current ? "#1a1500" : "#111827", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
                  <div style={{ fontSize: 36, minWidth: 48, textAlign: "center", opacity: earned ? 1 : 0.3 }}>{m.badge.split(" ")[0]}</div>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontWeight: 700, fontSize: 15 }}>{m.badge}</span>
                      <span style={{ fontSize: 13, color: "#4ADE80", fontWeight: 700 }}>{fmt(m.bonus)} bonus</span>
                    </div>
                    <div style={{ fontSize: 12, color: "#9DAED0", marginBottom: 8 }}>{m.label} · {directRefs.length}/{m.count} referrals</div>
                    <div style={{ height: 6, background: "#1E2D4A", borderRadius: 3, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${earned ? 100 : pct}%`, background: earned ? "#4ADE80" : "linear-gradient(90deg,#F5C842,#FB923C)", borderRadius: 3 }} />
                    </div>
                  </div>
                  <div style={{ minWidth: 80, textAlign: "center" }}>
                    {earned
                      ? <span style={{ background: "#4ADE8022", color: "#4ADE80", padding: "4px 12px", borderRadius: 20, fontSize: 12, fontWeight: 700 }}>✓ EARNED</span>
                      : <span style={{ color: "#9DAED0", fontSize: 12 }}>{m.count - Math.min(directRefs.length, m.count)} to go</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}

      {/* EARNINGS */}
      {tab === "earnings" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
            {[
              { label: "L1 Commissions", value: fmt(l1.reduce((s,r)=>s+(r.commission||0),0)), count: l1.length, color: "#4ADE80" },
              { label: "L2 Commissions", value: fmt(l2.reduce((s,r)=>s+(r.commission||0),0)), count: l2.length, color: "#60A5FA" },
              { label: "L3 Commissions", value: fmt(l3.reduce((s,r)=>s+(r.commission||0),0)), count: l3.length, color: "#A78BFA" },
            ].map(s => (
              <div key={s.label} style={{ background: "#111827", border: "1px solid #1E2D4A", borderRadius: 12, padding: "16px" }}>
                <div style={{ fontSize: 11, color: "#9DAED0", fontWeight: 600, marginBottom: 6 }}>{s.label}</div>
                <div style={{ fontSize: 22, fontWeight: 800, color: s.color }}>{s.value}</div>
                <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 4 }}>{s.count} payouts</div>
              </div>
            ))}
          </div>

          <div style={{ ...S.card, overflowX: "auto" }}>
            <h4 style={{ marginBottom: 16 }}>Full Earnings History</h4>
            {commissions.length === 0 && milestones.length === 0 ? (
              <div style={{ textAlign: "center", padding: "2rem", color: "#9DAED0" }}>No earnings yet. Share your link to start earning!</div>
            ) : (
              <table style={S.table}>
                <thead>
                  <tr>
                    <th style={S.th}>Type</th>
                    <th style={S.th}>From</th>
                    <th style={S.th}>Investment</th>
                    <th style={S.th}>Commission</th>
                    <th style={S.th}>Level</th>
                    <th style={S.th}>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {[...commissions, ...milestones].sort((a,b) => new Date(b.date) - new Date(a.date)).map((r, i) => (
                    <tr key={i}>
                      <td style={S.td}>
                        {r.type === "milestone"
                          ? <span style={{ color: "#F5C842" }}>🏆 Milestone</span>
                          : <span style={{ color: "#4ADE80" }}>💰 Commission</span>}
                      </td>
                      <td style={S.td}>{r.type === "milestone" ? r.badge : (r.refereeEmail || "—")}</td>
                      <td style={S.td}>{r.investmentAmt ? fmt(r.investmentAmt) : "—"}</td>
                      <td style={{ ...S.td, color: "#4ADE80", fontWeight: 700 }}>+{fmt(r.commission)}</td>
                      <td style={S.td}>{r.level ? `L${r.level}` : "—"}</td>
                      <td style={S.td}>{new Date(r.date).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {/* LEADERBOARD */}
      {tab === "leaderboard" && (
        <div style={{ ...S.card }}>
          <h4 style={{ marginBottom: 4 }}>🥇 Top Referrers This Month</h4>
          <p style={{ color: "#9DAED0", fontSize: 13, marginBottom: 20 }}>Compete with other investors. Top referrers earn bonus rewards each month.</p>
          {leaderboard.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2rem", color: "#9DAED0" }}>
              No referral activity yet. Be the first on the leaderboard!<br />
              <button style={{ ...S.btn("primary"), marginTop: 16 }} onClick={() => setTab("share")}>Start Referring →</button>
            </div>
          ) : (
            <table style={S.table}>
              <thead>
                <tr>
                  <th style={S.th}>Rank</th>
                  <th style={S.th}>Investor</th>
                  <th style={S.th}>Referrals</th>
                  <th style={S.th}>Earned</th>
                </tr>
              </thead>
              <tbody>
                {leaderboard.map((u, i) => (
                  <tr key={i}>
                    <td style={S.td}>
                      {i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : `#${i + 1}`}
                    </td>
                    <td style={{ ...S.td, fontWeight: 600 }}>{u.name}</td>
                    <td style={S.td}>{u.refs}</td>
                    <td style={{ ...S.td, color: "#4ADE80", fontWeight: 700 }}>{fmt(u.earned)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div style={{ marginTop: 20, background: "#0D1427", borderRadius: 8, padding: 14, fontSize: 13, color: "#9DAED0" }}>
            🎁 <strong style={{ color: "#F5C842" }}>Monthly Prize:</strong> Top referrer wins an extra <strong style={{ color: "#4ADE80" }}>$500 bonus</strong>. #2 wins $200. #3 wins $100. Prizes credited on the 1st of each month.
          </div>
        </div>
      )}
    </>
  );
}

// History Tab
function HistoryTab({ user }) {
  const data = db.get();
  const inv = data.investments.filter(i => i.userId === user.id);
  const txns = data.withdrawals.filter(w => w.userId === user.id);

  return (
    <>
      <h3 style={{ marginBottom: 12 }}>Investments</h3>
      {inv.length > 0 ? (
        <div style={{ ...S.card, overflowX: "auto" }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Plan</th><th style={S.th}>Amount</th>
                <th style={S.th}>ROI</th><th style={S.th}>Date</th><th style={S.th}>Status</th>
              </tr>
            </thead>
            <tbody>
              {inv.map(i => (
                <tr key={i.id}>
                  <td style={S.td}>{i.plan}</td>
                  <td style={S.td}>{fmt(i.amount)}</td>
                  <td style={S.td} ><span style={{ color: "#4ADE80" }}>{i.roi}%</span></td>
                  <td style={S.td}>{new Date(i.startDate).toLocaleDateString()}</td>
                  <td style={S.td}><span style={S.status(i.status)}>{i.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <div style={{ color: "#9DAED0", padding: "1rem 0" }}>No investments yet.</div>}

      <h3 style={{ marginTop: 32, marginBottom: 12 }}>Transactions</h3>
      {txns.length > 0 ? (
        <div style={{ ...S.card, overflowX: "auto" }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Type</th><th style={S.th}>Method</th>
                <th style={S.th}>Amount</th><th style={S.th}>Date</th><th style={S.th}>Status</th>
              </tr>
            </thead>
            <tbody>
              {txns.map(t => (
                <tr key={t.id}>
                  <td style={S.td}><span style={S.badge(t.type === "deposit" ? "#4ADE80" : "#F87171")}>{t.type}</span></td>
                  <td style={S.td}>{t.method}</td>
                  <td style={S.td}>{fmt(t.amount)}</td>
                  <td style={S.td}>{new Date(t.date).toLocaleDateString()}</td>
                  <td style={S.td}><span style={S.status(t.status)}>{t.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <div style={{ color: "#9DAED0", padding: "1rem 0" }}>No transactions yet.</div>}
    </>
  );
}

// ── Admin Panel ──────────────────────────────────────────────────────────────
function AdminPanel({ showToast }) {
  const [tab, setTab] = useState("payments");
  const [paymentDetails, setPaymentDetails] = useState(() => db.get().paymentDetails);
  const [editMethod, setEditMethod] = useState(null);
  const [form, setForm] = useState({ address: "", note: "" });

  const openEdit = (method) => {
    setEditMethod(method);
    setForm(paymentDetails[method.id] || { address: "", note: "" });
  };

  const savePayment = () => {
    const d = db.get();
    d.paymentDetails[editMethod.id] = { ...form };
    db.save(d);
    setPaymentDetails({ ...d.paymentDetails });
    setEditMethod(null);
    showToast(`${editMethod.name} details saved! ✓`);
  };

  const data = db.get();
  const allUsers = Object.values(data.users);
  const allTxns = data.withdrawals;
  const allInvestments = data.investments;

  const [actionModal, setActionModal] = React.useState(null); // { txn, action: "approve"|"reject" }
  const [adminNote, setAdminNote] = React.useState("");

  const openAction = (txn, action) => { setActionModal({ txn, action }); setAdminNote(""); };

  const confirmAction = () => {
    if (!actionModal) return;
    const { txn, action } = actionModal;
    const d = db.get();
    const t = d.withdrawals.find(x => x.id === txn.id);
    if (!t) return;

    if (action === "approve") {
      t.status = "completed";
      t.adminNote = adminNote || "Approved by admin.";
      t.processedAt = new Date().toISOString();
      // Credit balance on deposit approval
      if (t.type === "deposit") {
        const u = Object.values(d.users).find(u => u.id === t.userId);
        if (u) d.users[u.email].balance = (d.users[u.email].balance || 0) + t.amount;
      }
      // Refund balance on withdrawal approval (already deducted, so no change needed)
      db.save(d);
      pushNotification(t.userId, {
        title: t.type === "deposit" ? "✅ Deposit Confirmed!" : "✅ Withdrawal Approved!",
        message: t.type === "deposit"
          ? `Your deposit of ${fmt(t.amount)} has been confirmed and credited to your account. ${adminNote ? "Note: " + adminNote : ""}`
          : `Your withdrawal of ${fmt(t.amount)} via ${t.method} has been approved and is being processed. ${adminNote ? "Note: " + adminNote : "You will receive your funds shortly."}`,
        type: "success",
        txnId: t.id,
      });
      showToast("✅ Transaction approved & user notified!");
    } else {
      t.status = "rejected";
      t.adminNote = adminNote || "Rejected by admin.";
      t.processedAt = new Date().toISOString();
      // Refund balance on withdrawal rejection
      if (t.type === "withdrawal") {
        const u = Object.values(d.users).find(u => u.id === t.userId);
        if (u) d.users[u.email].balance = (d.users[u.email].balance || 0) + t.amount;
      }
      db.save(d);
      pushNotification(t.userId, {
        title: t.type === "deposit" ? "❌ Deposit Rejected" : "❌ Withdrawal Rejected",
        message: t.type === "deposit"
          ? `Your deposit of ${fmt(t.amount)} could not be confirmed. ${adminNote ? "Reason: " + adminNote : "Please contact support for assistance."}`
          : `Your withdrawal of ${fmt(t.amount)} was rejected. ${adminNote ? "Reason: " + adminNote : "Your funds have been refunded to your balance."} Please contact support if you have questions.`,
        type: "error",
        txnId: t.id,
      });
      showToast("❌ Transaction rejected & user notified", "error");
    }
    setActionModal(null);
    setAdminNote("");
  };

  const creditUser = (email, amount) => {
    const d = db.get();
    if (d.users[email]) {
      d.users[email].balance = (d.users[email].balance || 0) + amount;
      db.save(d);
      showToast(`Credited ${fmt(amount)} to ${email}`);
    }
  };

  const totalRevenue = allInvestments.reduce((s, i) => s + i.amount, 0);
  const totalPaid = allTxns.filter(t => t.type === "withdrawal" && t.status === "completed").reduce((s, t) => s + t.amount, 0);

  return (
    <div style={S.page}>
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, margin: 0 }}>🛡 Admin Panel</h1>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {["payments", "users", "transactions", "stats", "social", "security"].map(t => (
            <button key={t} style={S.tab(tab === t)} onClick={() => setTab(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* ── Payment Methods Config ── */}
      {tab === "payments" && (
        <>
          <div style={{ ...S.card, background: "#0D1427", marginBottom: 20, border: "1px solid #F5C84255" }}>
            <strong style={{ color: "#F5C842" }}>⚙️ Configure Payment Receiving Details</strong>
            <p style={{ color: "#9DAED0", fontSize: 14, marginTop: 4 }}>
              Set your wallet addresses and account details for each payment method. Users will see these when depositing.
            </p>
          </div>
          <div style={S.grid2}>
            {PAYMENT_METHODS.map(method => (
              <div key={method.id} style={S.card}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 20, color: "#F5C842" }}>{method.icon}</span>
                      <strong>{method.name}</strong>
                    </div>
                    <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 2 }}>{method.network}</div>
                  </div>
                  <button style={S.btn("sm")} onClick={() => openEdit(method)}>Edit</button>
                </div>
                {paymentDetails[method.id]?.address ? (
                  <div style={{ marginTop: 10, background: "#0D1427", borderRadius: 8, padding: 10 }}>
                    <div style={{ fontFamily: "monospace", fontSize: 12, wordBreak: "break-all", color: "#4ADE80" }}>
                      {paymentDetails[method.id].address}
                    </div>
                    {paymentDetails[method.id].note && (
                      <div style={{ fontSize: 12, color: "#9DAED0", marginTop: 4 }}>{paymentDetails[method.id].note}</div>
                    )}
                  </div>
                ) : (
                  <div style={{ marginTop: 8, color: "#F87171", fontSize: 13 }}>⚠ Not configured</div>
                )}
              </div>
            ))}
          </div>

          {editMethod && (
            <div style={S.modal} onClick={() => setEditMethod(null)}>
              <div style={S.modalBox} onClick={e => e.stopPropagation()}>
                <h3 style={{ marginBottom: 20 }}>Edit {editMethod.name}</h3>
                <label style={S.label}>Address / Account Details</label>
                <input style={{ ...S.input, marginBottom: 16 }} placeholder={editMethod.placeholder}
                  value={form.address} onChange={e => setForm({ ...form, address: e.target.value })} />
                <label style={S.label}>Additional Note (optional)</label>
                <input style={{ ...S.input, marginBottom: 20 }} placeholder="e.g. Network: TRC-20 only"
                  value={form.note} onChange={e => setForm({ ...form, note: e.target.value })} />
                <div style={{ display: "flex", gap: 8 }}>
                  <button style={{ ...S.btn("primary"), flex: 1 }} onClick={savePayment}>Save</button>
                  <button style={{ ...S.btn("secondary"), flex: 1 }} onClick={() => setEditMethod(null)}>Cancel</button>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── Users ── */}
      {tab === "users" && (
        <div style={{ ...S.card, overflowX: "auto" }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>Email</th><th style={S.th}>Name</th>
                <th style={S.th}>Balance</th><th style={S.th}>Invested</th>
                <th style={S.th}>Joined</th><th style={S.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {allUsers.filter(u => !u.isAdmin).map(u => (
                <tr key={u.id}>
                  <td style={S.td}>{u.email}</td>
                  <td style={S.td}>{u.name || "—"}</td>
                  <td style={S.td}><span style={{ color: "#F5C842" }}>{fmt(u.balance || 0)}</span></td>
                  <td style={S.td}>{fmt(u.totalInvested || 0)}</td>
                  <td style={S.td}>{new Date(u.joinDate).toLocaleDateString()}</td>
                  <td style={S.td}>
                    <button style={{ ...S.btn("sm"), marginRight: 6 }}
                      onClick={() => { const a = prompt(`Credit amount for ${u.email}:`); if (a) creditUser(u.email, parseFloat(a)); }}>
                      Credit
                    </button>
                  </td>
                </tr>
              ))}
              {allUsers.filter(u => !u.isAdmin).length === 0 && (
                <tr><td colSpan={6} style={{ ...S.td, textAlign: "center", color: "#9DAED0" }}>No users registered yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Transactions ── */}
      {tab === "transactions" && (
        <div style={{ ...S.card, overflowX: "auto" }}>
          <table style={S.table}>
            <thead>
              <tr>
                <th style={S.th}>ID</th><th style={S.th}>User</th><th style={S.th}>Type</th>
                <th style={S.th}>Method</th><th style={S.th}>Account Details</th>
                <th style={S.th}>Amount</th><th style={S.th}>Date</th>
                <th style={S.th}>Status</th><th style={S.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {allTxns.map(t => {
                const acc = t.accountDetails || {};
                const isBank = t.accountType?.includes("bank");
                const isEwallet = ["paypal","skrill","neteller","perfectmoney","cashapp","zelle"].includes(t.accountType);
                const txUser = Object.values(db.get().users).find(u => u.id === t.userId);
                return (
                  <tr key={t.id}>
                    <td style={S.td}><span style={{ fontFamily: "monospace", fontSize: 11 }}>{(t.id||"").slice(0,8)}</span></td>
                    <td style={S.td}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{txUser?.name || "—"}</div>
                      <div style={{ fontSize: 11, color: "#9DAED0" }}>{txUser?.email || ""}</div>
                    </td>
                    <td style={S.td}><span style={S.badge(t.type === "deposit" ? "#4ADE80" : "#F87171")}>{t.type}</span></td>
                    <td style={S.td}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{t.method}</div>
                      <div style={{ fontSize: 11, color: "#9DAED0" }}>{t.accountType || ""}</div>
                    </td>
                    <td style={{ ...S.td, maxWidth: 200 }}>
                      {t.type === "withdrawal" && Object.keys(acc).length > 0 ? (
                        <div style={{ background: "#0D1427", borderRadius: 8, padding: "8px 10px", fontSize: 12 }}>
                          {isBank ? (
                            <>
                              <div><span style={{ color: "#9DAED0" }}>Bank: </span>{acc.bankName}</div>
                              <div><span style={{ color: "#9DAED0" }}>Name: </span>{acc.accountName}</div>
                              <div><span style={{ color: "#9DAED0" }}>Acct: </span>{"****" + (acc.accountNumber||"").slice(-4)}</div>
                              {acc.swiftCode ? <div><span style={{ color: "#9DAED0" }}>SWIFT: </span>{acc.swiftCode}</div> : null}
                              {acc.iban ? <div><span style={{ color: "#9DAED0" }}>IBAN: </span>{acc.iban}</div> : null}
                              {acc.routingNumber ? <div><span style={{ color: "#9DAED0" }}>Routing: </span>{acc.routingNumber}</div> : null}
                            </>
                          ) : isEwallet ? (
                            <div><span style={{ color: "#9DAED0" }}>Account: </span>{acc.address}</div>
                          ) : (
                            <div style={{ fontFamily: "monospace", wordBreak: "break-all", fontSize: 11 }}>{acc.address || t.address || "—"}</div>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: "#9DAED0", fontSize: 12 }}>—</span>
                      )}
                    </td>
                    <td style={{ ...S.td, fontWeight: 700 }}>{fmt(t.amount)}</td>
                    <td style={S.td}>{new Date(t.date).toLocaleDateString()}</td>
                    <td style={S.td}><span style={S.status(t.status)}>{t.status}</span></td>
                    <td style={S.td}>
                      {t.status === "pending" && (
                        <div style={{ display: "flex", gap: 6 }}>
                          <button style={{ ...S.btn("sm"), background: "#166534", color: "#fff" }} onClick={() => openAction(t, "approve")}>✓ Approve</button>
                          <button style={{ ...S.btn("sm"), background: "#7f1d1d", color: "#fff" }} onClick={() => openAction(t, "reject")}>✗ Reject</button>
                        </div>
                      )}
                      {t.status !== "pending" && t.adminNote && (
                        <div style={{ fontSize: 11, color: "#9DAED0", maxWidth: 160, marginTop: 4 }}>📝 {t.adminNote}</div>
                      )}
                    </td>
                  </tr>
                );
              })}
              {allTxns.length === 0 && (
                <tr><td colSpan={9} style={{ ...S.td, textAlign: "center", color: "#9DAED0" }}>No transactions yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Stats ── */}
      {tab === "stats" && (
        <>
        <div style={{ background: "#1A0A0A", border: "1px solid #F8717144", borderRadius: 12, padding: "14px 18px", marginBottom: 20, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
          <div>
            <div style={{ fontWeight: 700, color: "#F87171", fontSize: 14 }}>⚠️ Danger Zone</div>
            <div style={{ color: "#9DAED0", fontSize: 12, marginTop: 2 }}>Permanently erase all platform data. This cannot be undone.</div>
          </div>
          <button style={{ ...S.btn("danger"), fontSize: 13 }} onClick={() => {
            if (window.confirm("Are you sure? This will DELETE all users, investments, and transactions permanently.")) {
              db.clear();
              sessionManager.clear(); securityLog.log("user_logout");
              window.location.reload();
            }
          }}>🗑 Reset All Data</button>
        </div>
        <div style={S.grid3}>
          {[
            { label: "Total Users", value: fmtNum(allUsers.filter(u => !u.isAdmin).length), color: "#F5C842" },
            { label: "Total Investments", value: fmt(totalRevenue), color: "#60A5FA" },
            { label: "Total Paid Out", value: fmt(totalPaid), color: "#4ADE80" },
            { label: "Active Investments", value: allInvestments.filter(i => i.status === "active").length, color: "#A78BFA" },
            { label: "Pending Deposits", value: allTxns.filter(t => t.type === "deposit" && t.status === "pending").length, color: "#FCD34D" },
            { label: "Pending Withdrawals", value: allTxns.filter(t => t.type === "withdrawal" && t.status === "pending").length, color: "#F87171" },
            { label: "Security Events (24h)", value: (db.get().securityLog || []).filter(l => new Date(l.timestamp) > new Date(Date.now() - 86400000)).length, color: "#A78BFA" },
          ].map(s => (
            <div key={s.label} style={S.stat}>
              <div style={{ fontSize: 13, color: "#9DAED0" }}>{s.label}</div>
              <div style={{ fontSize: 26, fontWeight: 800, color: s.color, marginTop: 4 }}>{s.value}</div>
            </div>
          ))}
        </div>
        </>
      )}

      {/* ── Social Links Config ── */}
      {tab === "social" && <AdminSocialLinks />}
      {tab === "security" && <AdminSecurityLog />}
      {/* ── Approve / Reject Modal ── */}
      {actionModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
          <div style={{ background: "#161D2E", border: "1px solid #1E2D4A", borderRadius: 16, padding: 28, width: "100%", maxWidth: 480, boxShadow: "0 20px 60px rgba(0,0,0,0.6)" }}>
            <div style={{ fontSize: 28, textAlign: "center", marginBottom: 8 }}>
              {actionModal.action === "approve" ? "✅" : "❌"}
            </div>
            <div style={{ fontWeight: 800, fontSize: 20, textAlign: "center", marginBottom: 4 }}>
              {actionModal.action === "approve" ? "Confirm Approval" : "Confirm Rejection"}
            </div>
            <div style={{ color: "#9DAED0", fontSize: 13, textAlign: "center", marginBottom: 20 }}>
              {actionModal.action === "approve" ? "Approve" : "Reject"} {actionModal.txn.type} of <strong style={{ color: "#F5C842" }}>{fmt(actionModal.txn.amount)}</strong> for <strong>{(Object.values(db.get().users).find(u => u.id === actionModal.txn.userId))?.name || "user"}</strong>?
            </div>

            {/* Transaction summary */}
            <div style={{ background: "#0D1427", borderRadius: 10, padding: "12px 16px", marginBottom: 16, fontSize: 13 }}>
              {[
                ["Type", actionModal.txn.type.charAt(0).toUpperCase() + actionModal.txn.type.slice(1)],
                ["Amount", fmt(actionModal.txn.amount)],
                ["Method", actionModal.txn.method],
                ["Date", new Date(actionModal.txn.date).toLocaleString()],
              ].map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ color: "#9DAED0" }}>{k}</span>
                  <span style={{ fontWeight: 600 }}>{v}</span>
                </div>
              ))}
              {actionModal.txn.type === "withdrawal" && actionModal.txn.accountDetails && (
                <div style={{ borderTop: "1px solid #1E2D4A", paddingTop: 8, marginTop: 4 }}>
                  <div style={{ color: "#9DAED0", marginBottom: 4 }}>Send to:</div>
                  {actionModal.txn.accountDetails.address && <div style={{ fontFamily: "monospace", fontSize: 12, wordBreak: "break-all" }}>{actionModal.txn.accountDetails.address}</div>}
                  {actionModal.txn.accountDetails.bankName && <div>Bank: {actionModal.txn.accountDetails.bankName} · Acct: ****{(actionModal.txn.accountDetails.accountNumber||"").slice(-4)}</div>}
                </div>
              )}
            </div>

            {/* Admin note */}
            <div style={{ marginBottom: 20 }}>
              <label style={S.label}>Message to User (optional)</label>
              <textarea
                style={{ ...S.input, height: 80, resize: "vertical" }}
                placeholder={actionModal.action === "approve"
                  ? "e.g. Payment sent via blockchain. TX hash: 0xabc..."
                  : "e.g. Please resubmit with a valid wallet address."}
                value={adminNote}
                onChange={e => setAdminNote(e.target.value)}
              />
              <div style={{ fontSize: 11, color: "#9DAED0", marginTop: 4 }}>This message will appear in the user's notification.</div>
            </div>

            {/* Withdrawal refund notice */}
            {actionModal.action === "reject" && actionModal.txn.type === "withdrawal" && (
              <div style={{ background: "#1A1000", border: "1px solid #F5C84233", borderRadius: 8, padding: "10px 14px", fontSize: 13, color: "#F5C842", marginBottom: 16 }}>
                ⚠️ Rejecting this withdrawal will automatically refund <strong>{fmt(actionModal.txn.amount)}</strong> back to the user's balance.
              </div>
            )}

            <div style={{ display: "flex", gap: 10 }}>
              <button style={{ ...S.btn("ghost"), flex: 1 }} onClick={() => setActionModal(null)}>Cancel</button>
              <button
                style={{ ...S.btn(actionModal.action === "approve" ? "primary" : "danger"), flex: 2 }}
                onClick={confirmAction}
              >
                {actionModal.action === "approve" ? "✅ Approve & Notify User" : "❌ Reject & Notify User"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ── Admin Security Log ────────────────────────────────────────────────────────
function AdminSecurityLog() {
  const logs = [...(db.get().securityLog || [])].reverse();
  const [filter, setFilter] = React.useState("all");

  const EVENT_LABELS = {
    user_login:    { label: "User Login",    color: "#4ADE80", icon: "✅" },
    admin_login:   { label: "Admin Login",   color: "#60A5FA", icon: "🛡️" },
    user_register: { label: "Registration",  color: "#A78BFA", icon: "👤" },
    login_failed:  { label: "Failed Login",  color: "#F87171", icon: "❌" },
    user_logout:   { label: "Logout",        color: "#9DAED0", icon: "👋" },
    auth_error:    { label: "Auth Error",    color: "#F97316", icon: "⚠️" },
  };

  const filtered = filter === "all" ? logs : logs.filter(l => l.event === filter);
  const last24h = logs.filter(l => new Date(l.timestamp) > new Date(Date.now() - 86400000));
  const failed = logs.filter(l => l.event === "login_failed");
  const unique = [...new Set(logs.map(l => l.details?.email).filter(Boolean))];

  const rl = (() => { try { return JSON.parse(localStorage.getItem("nexavest_ratelimit") || "{}"); } catch { return {}; } })();
  const locked = Object.entries(rl).filter(([, v]) => v.lockedUntil && Date.now() < v.lockedUntil);

  const unlockAccount = (email) => {
    try {
      const data = JSON.parse(localStorage.getItem("nexavest_ratelimit") || "{}");
      delete data[email];
      localStorage.setItem("nexavest_ratelimit", JSON.stringify(data));
      window.location.reload();
    } catch {}
  };

  return (
    <div>
      <div style={{ fontWeight: 800, fontSize: 20, marginBottom: 6 }}>🔐 Security Center</div>
      <div style={{ color: "#9DAED0", fontSize: 13, marginBottom: 20 }}>Monitor all authentication and security events in real-time</div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Events (24h)", value: last24h.length, color: "#60A5FA", icon: "📊" },
          { label: "Failed Logins", value: failed.length, color: "#F87171", icon: "❌" },
          { label: "Unique Accounts", value: unique.length, color: "#A78BFA", icon: "👤" },
          { label: "Locked Accounts", value: locked.length, color: "#F97316", icon: "🔒" },
          { label: "Total Events", value: logs.length, color: "#4ADE80", icon: "📋" },
        ].map(s => (
          <div key={s.label} style={{ background: "#111827", border: "1px solid #1C2538", borderRadius: 12, padding: "14px 16px" }}>
            <div style={{ fontSize: 20 }}>{s.icon}</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: s.color, margin: "4px 0 2px" }}>{s.value}</div>
            <div style={{ fontSize: 11, color: "#9DAED0" }}>{s.label}</div>
          </div>
        ))}
      </div>

      {locked.length > 0 && (
        <div style={{ background: "#1A0A00", border: "1px solid #F9731644", borderRadius: 12, padding: "16px 20px", marginBottom: 20 }}>
          <div style={{ fontWeight: 700, color: "#F97316", marginBottom: 12 }}>🔒 Locked Accounts ({locked.length})</div>
          {locked.map(([email, data]) => (
            <div key={email} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #1C2538" }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{email}</div>
                <div style={{ fontSize: 11, color: "#9DAED0" }}>{data.attempts} attempts · Unlocks {new Date(data.lockedUntil).toLocaleTimeString()}</div>
              </div>
              <button style={{ ...S.btn("sm"), background: "#166534", color: "#fff" }} onClick={() => unlockAccount(email)}>🔓 Unlock</button>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }}>
        {[["all","All"],...Object.entries(EVENT_LABELS).map(([k,v])=>[k,v.icon+" "+v.label])].map(([f,label]) => (
          <button key={f} onClick={() => setFilter(f)} style={{ padding:"6px 12px", borderRadius:8, border:"none", cursor:"pointer", fontSize:12, fontWeight:600, fontFamily:"inherit", background: filter===f?"#1A56DB":"#0D1427", color: filter===f?"#fff":"#9DAED0" }}>{label}</button>
        ))}
      </div>

      <div style={{ background: "#111827", border: "1px solid #1C2538", borderRadius: 12, overflow: "hidden", marginBottom: 20 }}>
        <div style={{ overflowX: "auto" }}>
          <table style={S.table}>
            <thead><tr>
              <th style={S.th}>Event</th><th style={S.th}>Account</th><th style={S.th}>Details</th><th style={S.th}>Browser</th><th style={S.th}>Time</th>
            </tr></thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={5} style={{ ...S.td, textAlign:"center", color:"#9DAED0", padding:"2rem" }}>No security events yet</td></tr>
              ) : filtered.slice(0,100).map(log => {
                const ev = EVENT_LABELS[log.event] || { label: log.event, color:"#9DAED0", icon:"📋" };
                return (
                  <tr key={log.id}>
                    <td style={S.td}><span style={{ background:ev.color+"22", color:ev.color, padding:"3px 10px", borderRadius:20, fontSize:12, fontWeight:700, whiteSpace:"nowrap" }}>{ev.icon} {ev.label}</span></td>
                    <td style={{ ...S.td, fontFamily:"monospace", fontSize:12 }}>{log.details?.email||"—"}</td>
                    <td style={{ ...S.td, fontSize:12, color:"#9DAED0" }}>{log.details?.reason||log.details?.name||(log.details?.attempts?`Attempt #${log.details.attempts}`:"—")}</td>
                    <td style={{ ...S.td, fontSize:11, color:"#9DAED0", maxWidth:160 }}><div style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{log.userAgent}</div></td>
                    <td style={{ ...S.td, fontSize:12, color:"#9DAED0", whiteSpace:"nowrap" }}>{new Date(log.timestamp).toLocaleString("en-US",{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit",second:"2-digit"})}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div style={{ background:"#0D1427", border:"1px solid #1C2538", borderRadius:12, padding:"18px 20px" }}>
        <div style={{ fontWeight:700, marginBottom:12 }}>🛡️ Security Status</div>
        {[
          [true,  "Passwords hashed with SHA-256 before storage"],
          [true,  "Brute-force protection: lock after 5 failed attempts (15 min)"],
          [true,  "Sessions expire automatically after 24 hours"],
          [true,  "All inputs sanitized against XSS attacks"],
          [true,  "Security events logged with timestamps & browser fingerprint"],
          [false, "Production: Use HTTPS/SSL certificate on your domain"],
          [false, "Production: Move to Supabase backend for server-side security"],
          [false, "Production: Enable 2FA for admin account"],
        ].map(([ok,text],i) => (
          <div key={i} style={{ display:"flex", gap:10, marginBottom:8, fontSize:13 }}>
            <span style={{ color:ok?"#4ADE80":"#F5C842", flexShrink:0 }}>{ok?"✅":"⚠️"}</span>
            <span style={{ color:ok?"#9DAED0":"#F5C842" }}>{text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Admin Social Links Config ─────────────────────────────────────────────────
function AdminSocialLinks() {
  const [links, setLinksState] = React.useState(() => db.get().socialLinks || {});
  const [saved, setSaved] = React.useState(false);

  const update = (field, val) => setLinksState(prev => ({ ...prev, [field]: val }));

  const save = () => {
    const d = db.get();
    d.socialLinks = links;
    db.save(d);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const fields = [
    {
      id: "whatsapp",
      icon: "💬",
      name: "WhatsApp",
      color: "#25D366",
      urlField: "whatsapp",
      labelField: "whatsappLabel",
      urlPlaceholder: "https://wa.me/1234567890  or  https://chat.whatsapp.com/yourchannellink",
      labelPlaceholder: "e.g. Chat on WhatsApp",
      hint: "Paste your WhatsApp number link (wa.me/...) or WhatsApp Channel link",
    },
    {
      id: "telegram",
      icon: "✈️",
      name: "Telegram",
      color: "#0088CC",
      urlField: "telegram",
      labelField: "telegramLabel",
      urlPlaceholder: "https://t.me/yourchannelname",
      labelPlaceholder: "e.g. Join our Telegram Channel",
      hint: "Paste your Telegram channel or group link",
    },
    {
      id: "tiktok",
      icon: "🎵",
      name: "TikTok",
      color: "#FF0050",
      urlField: "tiktok",
      labelField: "tiktokLabel",
      urlPlaceholder: "https://www.tiktok.com/@yourusername",
      labelPlaceholder: "e.g. Follow us on TikTok",
      hint: "Paste your TikTok profile or page link",
    },
  ];

  return (
    <div style={{ maxWidth: 700 }}>
      <div style={{ background: "#0D1427", border: "1px solid #F5C84244", borderRadius: 14, padding: "18px 22px", marginBottom: 24 }}>
        <div style={{ fontWeight: 700, color: "#F5C842", fontSize: 16, marginBottom: 4 }}>📣 Support & Social Links</div>
        <div style={{ color: "#9DAED0", fontSize: 13 }}>
          Add your WhatsApp, Telegram, and TikTok links here. They will appear on the <strong style={{ color: "#F1F5F9" }}>Support</strong> tab visible to all users.
        </div>
      </div>

      {saved && (
        <div style={{ background: "#0D2010", border: "1px solid #4ADE8044", borderRadius: 10, padding: "12px 16px", color: "#4ADE80", fontSize: 14, marginBottom: 18 }}>
          ✅ Social links saved successfully! Users can now see them on the Support page.
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {fields.map(f => (
          <div key={f.id} style={{ background: "#111827", border: `1px solid ${f.color}33`, borderRadius: 14, padding: "20px 22px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              <span style={{ fontSize: 28 }}>{f.icon}</span>
              <div>
                <div style={{ fontWeight: 700, fontSize: 16, color: f.color }}>{f.name}</div>
                <div style={{ fontSize: 12, color: "#9DAED0" }}>{f.hint}</div>
              </div>
              {links[f.urlField] && (
                <a href={links[f.urlField]} target="_blank" rel="noopener noreferrer"
                  style={{ marginLeft: "auto", background: f.color, color: "#fff", padding: "6px 14px", borderRadius: 8, fontSize: 12, fontWeight: 700, textDecoration: "none" }}>
                  Test Link ↗
                </a>
              )}
            </div>
            <div style={{ marginBottom: 12 }}>
              <label style={S.label}>{f.name} Link / URL</label>
              <input
                style={S.input}
                placeholder={f.urlPlaceholder}
                value={links[f.urlField] || ""}
                onChange={e => update(f.urlField, e.target.value)}
              />
            </div>
            <div>
              <label style={S.label}>Button Label (what users see)</label>
              <input
                style={S.input}
                placeholder={f.labelPlaceholder}
                value={links[f.labelField] || ""}
                onChange={e => update(f.labelField, e.target.value)}
              />
            </div>
          </div>
        ))}
      </div>

      <button style={{ ...S.btn("primary"), width: "100%", marginTop: 24, padding: "14px" }} onClick={save}>
        💾 Save Social Links
      </button>

      <div style={{ background: "#111827", border: "1px solid #1E2D4A", borderRadius: 12, padding: "16px 20px", marginTop: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 14 }}>👁 Preview — how it looks to users</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {fields.map(f => (
            <div key={f.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0D1427", borderRadius: 10, padding: "12px 16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 22 }}>{f.icon}</span>
                <div>
                  <div style={{ fontWeight: 600, color: f.color, fontSize: 14 }}>{links[f.labelField] || f.labelPlaceholder.replace("e.g. ", "")}</div>
                  <div style={{ fontSize: 11, color: "#9DAED0" }}>{links[f.urlField] ? "✓ Link configured" : "⚠ No link set yet"}</div>
                </div>
              </div>
              <div style={{ background: f.color, color: "#fff", padding: "6px 14px", borderRadius: 8, fontSize: 12, fontWeight: 700, opacity: links[f.urlField] ? 1 : 0.4 }}>
                {f.id === "tiktok" ? "Follow & Like →" : "Open →"}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}



// ── Notifications Tab ─────────────────────────────────────────────────────────
function NotificationsTab({ user, refreshUser }) {
  const [filter, setFilter] = React.useState("all"); // all | unread | success | error

  const markRead = (id) => {
    const d = db.get();
    const n = d.notifications.find(n => n.id === id);
    if (n) { n.read = true; db.save(d); refreshUser(); }
  };

  const markAllRead = () => {
    const d = db.get();
    (d.notifications || []).filter(n => n.userId === user.id).forEach(n => n.read = true);
    db.save(d);
    refreshUser();
  };

  const deleteNotif = (id) => {
    const d = db.get();
    d.notifications = (d.notifications || []).filter(n => n.id !== id);
    db.save(d);
    refreshUser();
  };

  const allNotifs = (db.get().notifications || [])
    .filter(n => n.userId === user.id)
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  const filtered = filter === "all" ? allNotifs
    : filter === "unread" ? allNotifs.filter(n => !n.read)
    : allNotifs.filter(n => n.type === filter);

  const unreadCount = allNotifs.filter(n => !n.read).length;

  const typeStyle = (type) => ({
    success: { bg: "#0D2010", border: "#4ADE8044", icon: "✅", color: "#4ADE80" },
    error:   { bg: "#1A0808", border: "#EF444444", icon: "❌", color: "#EF4444" },
    warning: { bg: "#1A1000", border: "#F5C84244", icon: "⚠️", color: "#F5C842" },
    info:    { bg: "#0D1427", border: "#60A5FA44", icon: "ℹ️", color: "#60A5FA" },
  }[type] || { bg: "#0D1427", border: "#1E2D4A", icon: "🔔", color: "#9DAED0" });

  return (
    <div style={{ maxWidth: 680 }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, flexWrap: "wrap", gap: 10 }}>
        <div>
          <div style={{ fontWeight: 800, fontSize: 20 }}>🔔 Notifications</div>
          <div style={{ color: "#9DAED0", fontSize: 13, marginTop: 2 }}>
            {unreadCount > 0 ? <span style={{ color: "#EF4444", fontWeight: 700 }}>{unreadCount} unread</span> : "All caught up!"}
            {" · "}{allNotifs.length} total
          </div>
        </div>
        {unreadCount > 0 && (
          <button style={{ ...S.btn("ghost"), fontSize: 13 }} onClick={markAllRead}>✓ Mark all as read</button>
        )}
      </div>

      {/* Filter tabs */}
      <div style={{ display: "flex", gap: 6, marginBottom: 20, flexWrap: "wrap" }}>
        {[
          ["all", "All", allNotifs.length],
          ["unread", "Unread", unreadCount],
          ["success", "✅ Approved", allNotifs.filter(n => n.type === "success").length],
          ["error", "❌ Rejected", allNotifs.filter(n => n.type === "error").length],
          ["info", "ℹ️ Info", allNotifs.filter(n => n.type === "info").length],
        ].map(([f, label, count]) => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding: "7px 14px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 700, fontFamily: "inherit",
            background: filter === f ? "#1A56DB" : "#0D1427",
            color: filter === f ? "#fff" : "#9DAED0",
          }}>{label} {count > 0 && <span style={{ background: filter === f ? "rgba(255,255,255,0.25)" : "#1E2D4A", borderRadius: 20, padding: "1px 7px", marginLeft: 4 }}>{count}</span>}</button>
        ))}
      </div>

      {/* Notification list */}
      {filtered.length === 0 ? (
        <div style={{ ...S.card, textAlign: "center", padding: "3rem 2rem" }}>
          <div style={{ fontSize: 52, marginBottom: 16 }}>🔔</div>
          <div style={{ fontWeight: 700, fontSize: 17, marginBottom: 8 }}>No Notifications</div>
          <div style={{ color: "#9DAED0", fontSize: 14 }}>
            {filter === "all" ? "You're all caught up! Notifications about your deposits, withdrawals, and account activity will appear here." : `No ${filter} notifications.`}
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {filtered.map(n => {
            const ts = typeStyle(n.type);
            return (
              <div key={n.id}
                onClick={() => !n.read && markRead(n.id)}
                style={{
                  background: n.read ? "#0D1427" : ts.bg,
                  border: `1px solid ${n.read ? "#1E2D4A" : ts.border}`,
                  borderRadius: 12, padding: "16px 18px",
                  cursor: n.read ? "default" : "pointer",
                  transition: "all 0.15s",
                  opacity: n.read ? 0.75 : 1,
                  position: "relative",
                }}
              >
                {!n.read && (
                  <div style={{ position: "absolute", top: 16, right: 16, width: 8, height: 8, borderRadius: "50%", background: "#EF4444" }} />
                )}
                <div style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
                  <div style={{ fontSize: 28, flexShrink: 0, marginTop: 2 }}>{ts.icon}</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 4, marginBottom: 6 }}>
                      <div style={{ fontWeight: 700, fontSize: 15, color: n.read ? "#F1F5F9" : ts.color }}>{n.title}</div>
                      <div style={{ fontSize: 11, color: "#9DAED0", flexShrink: 0 }}>
                        {new Date(n.date).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                      </div>
                    </div>
                    <div style={{ fontSize: 14, color: "#9DAED0", lineHeight: 1.6 }}>{n.message}</div>
                    <div style={{ display: "flex", gap: 10, marginTop: 10, alignItems: "center" }}>
                      {!n.read && (
                        <button onClick={e => { e.stopPropagation(); markRead(n.id); }} style={{ ...S.btn("ghost"), padding: "4px 12px", fontSize: 11 }}>Mark read</button>
                      )}
                      <button onClick={e => { e.stopPropagation(); deleteNotif(n.id); }} style={{ background: "transparent", border: "none", color: "#9DAED0", fontSize: 11, cursor: "pointer", padding: "4px 8px" }}>🗑 Delete</button>
                      {n.read && <span style={{ fontSize: 11, color: "#9DAED0" }}>✓ Read</span>}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Support Tab ──────────────────────────────────────────────────────────────
function SupportTab() {
  const links = db.get().socialLinks || {};
  const [submitted, setSubmitted] = React.useState(false);
  const [msg, setMsg] = React.useState({ name: "", email: "", subject: "", message: "" });

  const submitMsg = () => {
    if (!msg.name || !msg.message) return;
    setSubmitted(true);
    setTimeout(() => setSubmitted(false), 4000);
    setMsg({ name: "", email: "", subject: "", message: "" });
  };

  const channels = [
    {
      id: "whatsapp",
      icon: "💬",
      name: "WhatsApp",
      label: links.whatsappLabel || "Chat on WhatsApp",
      url: links.whatsapp,
      desc: "Chat directly with our support team. Fastest response — usually within minutes.",
      color: "#25D366",
      bg: "#0D1F0F",
      border: "#25D36644",
      cta: "Open WhatsApp →",
    },
    {
      id: "telegram",
      icon: "✈️",
      name: "Telegram",
      label: links.telegramLabel || "Join Telegram Channel",
      url: links.telegram,
      desc: "Join our Telegram channel for announcements, tips, and community support.",
      color: "#0088CC",
      bg: "#0A1520",
      border: "#0088CC44",
      cta: "Open Telegram →",
    },
    {
      id: "tiktok",
      icon: "🎵",
      name: "TikTok",
      label: links.tiktokLabel || "Follow on TikTok",
      url: links.tiktok,
      desc: "Follow our TikTok for investment tips, platform updates, and community highlights.",
      color: "#FF0050",
      bg: "#1A0A10",
      border: "#FF005044",
      cta: "Follow & Like →",
    },
  ];

  return (
    <div style={{ maxWidth: 720 }}>
      {/* Header */}
      <div style={{ background: "linear-gradient(135deg,#0D1427,#111827)", border: "1px solid #1E2D4A", borderRadius: 16, padding: "28px 24px", marginBottom: 24, textAlign: "center" }}>
        <div style={{ fontSize: 48, marginBottom: 12 }}>🎧</div>
        <h2 style={{ fontSize: 24, fontWeight: 800, marginBottom: 8 }}>We're Here to Help</h2>
        <p style={{ color: "#9DAED0", fontSize: 15, lineHeight: 1.6, maxWidth: 480, margin: "0 auto" }}>
          Reach our support team instantly via WhatsApp or Telegram, or follow us on TikTok for tips and updates.
        </p>
        <div style={{ display: "flex", gap: 8, justifyContent: "center", marginTop: 16, flexWrap: "wrap" }}>
          <span style={{ background: "#4ADE8022", color: "#4ADE80", fontSize: 12, padding: "4px 12px", borderRadius: 20, fontWeight: 600 }}>⚡ Fast Response</span>
          <span style={{ background: "#60A5FA22", color: "#60A5FA", fontSize: 12, padding: "4px 12px", borderRadius: 20, fontWeight: 600 }}>🌍 24/7 Available</span>
          <span style={{ background: "#F5C84222", color: "#F5C842", fontSize: 12, padding: "4px 12px", borderRadius: 20, fontWeight: 600 }}>🔒 Secure & Private</span>
        </div>
      </div>

      {/* Social Channels */}
      <div style={{ display: "flex", flexDirection: "column", gap: 14, marginBottom: 28 }}>
        {channels.map(ch => (
          <div key={ch.id} style={{ background: ch.bg, border: `1px solid ${ch.border}`, borderRadius: 14, padding: "20px 22px", display: "flex", alignItems: "center", gap: 18, flexWrap: "wrap" }}>
            <div style={{ fontSize: 36, flexShrink: 0 }}>{ch.icon}</div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontWeight: 700, fontSize: 17, color: ch.color, marginBottom: 4 }}>{ch.label}</div>
              <div style={{ fontSize: 13, color: "#9DAED0", lineHeight: 1.5 }}>{ch.desc}</div>
            </div>
            {ch.url ? (
              <a
                href={ch.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{ background: ch.color, color: "#fff", padding: "10px 20px", borderRadius: 10, fontWeight: 700, fontSize: 14, textDecoration: "none", flexShrink: 0, display: "inline-block" }}
              >
                {ch.cta}
              </a>
            ) : (
              <div style={{ color: "#9DAED0", fontSize: 13, fontStyle: "italic", flexShrink: 0 }}>Coming soon</div>
            )}
          </div>
        ))}
      </div>

      {/* FAQ */}
      <div style={{ background: "#111827", border: "1px solid #1E2D4A", borderRadius: 14, padding: "22px", marginBottom: 24 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 18 }}>❓ Frequently Asked Questions</h3>
        {[
          { q: "How long does a deposit take?", a: "Crypto deposits are confirmed within 30–60 minutes after network confirmation. Bank transfers may take 1–2 business days." },
          { q: "When are withdrawals processed?", a: "Withdrawal requests are reviewed and processed within 24 hours, Monday to Saturday." },
          { q: "Is my investment safe?", a: "We use advanced security measures and cold storage for all funds. Your capital is protected by our guarantee policy." },
          { q: "How do I earn from referrals?", a: "Share your unique referral link. You earn 10% (Level 1), 3% (Level 2), and 1% (Level 3) on every investment your referrals make." },
          { q: "Can I invest from any country?", a: "Yes! We support investors from 150+ countries with 13 global payment methods including crypto and bank transfer." },
          { q: "How do I track my earnings?", a: "Log in to your dashboard and go to Overview — your balance, active investments, and daily earnings are shown in real time." },
        ].map((item, i) => (
          <FaqItem key={i} q={item.q} a={item.a} />
        ))}
      </div>

      {/* Contact form */}
      <div style={{ background: "#111827", border: "1px solid #1E2D4A", borderRadius: 14, padding: "22px" }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>📩 Send a Message</h3>
        <p style={{ color: "#9DAED0", fontSize: 13, marginBottom: 18 }}>For non-urgent queries, fill out the form below and we'll respond within 24 hours.</p>
        {submitted && (
          <div style={{ background: "#0D2010", border: "1px solid #4ADE8044", borderRadius: 10, padding: "12px 16px", color: "#4ADE80", fontSize: 14, marginBottom: 16 }}>
            ✅ Message sent! We'll get back to you within 24 hours.
          </div>
        )}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <div>
            <label style={S.label}>Your Name</label>
            <input style={S.input} placeholder="John Smith" value={msg.name} onChange={e => setMsg({ ...msg, name: e.target.value })} />
          </div>
          <div>
            <label style={S.label}>Email Address</label>
            <input style={S.input} type="email" placeholder="you@email.com" value={msg.email} onChange={e => setMsg({ ...msg, email: e.target.value })} />
          </div>
        </div>
        <div style={{ marginBottom: 12 }}>
          <label style={S.label}>Subject</label>
          <select style={S.input} value={msg.subject} onChange={e => setMsg({ ...msg, subject: e.target.value })}>
            <option value="">Select a topic...</option>
            {["Deposit issue","Withdrawal delay","Account problem","Referral question","Investment query","Other"].map(o => <option key={o}>{o}</option>)}
          </select>
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={S.label}>Message</label>
          <textarea style={{ ...S.input, height: 100, resize: "vertical" }} placeholder="Describe your issue or question in detail..." value={msg.message} onChange={e => setMsg({ ...msg, message: e.target.value })} />
        </div>
        <button style={{ ...S.btn("primary"), width: "100%" }} onClick={submitMsg}>Send Message →</button>
      </div>
    </div>
  );
}

// ── FAQ Accordion Item ────────────────────────────────────────────────────────
function FaqItem({ q, a }) {
  const [open, setOpen] = React.useState(false);
  return (
    <div style={{ borderBottom: "1px solid #1E2D4A", paddingBottom: 12, marginBottom: 12 }}>
      <div
        onClick={() => setOpen(!open)}
        style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", userSelect: "none" }}
      >
        <span style={{ fontWeight: 600, fontSize: 14, color: open ? "#F5C842" : "#F1F5F9" }}>{q}</span>
        <span style={{ color: "#9DAED0", fontSize: 18, fontWeight: 300, transition: "transform 0.2s", transform: open ? "rotate(45deg)" : "none" }}>+</span>
      </div>
      {open && (
        <div style={{ marginTop: 10, fontSize: 13, color: "#9DAED0", lineHeight: 1.7, paddingRight: 24 }}>{a}</div>
      )}
    </div>
  );
}

// ── Modal ────────────────────────────────────────────────────────────────────
function Modal({ modal, close }) {
  return (
    <div style={S.modal} onClick={close}>
      <div style={S.modalBox} onClick={e => e.stopPropagation()}>
        <h3 style={{ marginBottom: 16 }}>{modal.title}</h3>
        <p style={{ color: "#9DAED0" }}>{modal.body}</p>
        <button style={{ ...S.btn("primary"), marginTop: 20 }} onClick={close}>Close</button>
      </div>
    </div>
  );
}
