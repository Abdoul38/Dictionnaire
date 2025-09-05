// utils/security.js - Utilitaires de sécurité pour le Dictionnaire Zarma
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

/**
 * Génère un token sécurisé aléatoirement
 * @param {number} length - Longueur du token
 * @returns {string} Token généré
 */
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Génère un salt pour le hachage
 * @param {number} rounds - Nombre de rounds bcrypt
 * @returns {Promise<string>} Salt généré
 */
async function generateSalt(rounds = 12) {
  return await bcrypt.genSalt(rounds);
}

/**
 * Hache un mot de passe de manière sécurisée
 * @param {string} password - Mot de passe à hacher
 * @param {number} rounds - Nombre de rounds bcrypt
 * @returns {Promise<string>} Hash du mot de passe
 */
async function hashPassword(password, rounds = 12) {
  try {
    return await bcrypt.hash(password, rounds);
  } catch (error) {
    throw new Error('Erreur lors du hachage du mot de passe');
  }
}

/**
 * Vérifie un mot de passe contre son hash
 * @param {string} password - Mot de passe en clair
 * @param {string} hash - Hash à vérifier
 * @returns {Promise<boolean>} Résultat de la vérification
 */
async function verifyPassword(password, hash) {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    throw new Error('Erreur lors de la vérification du mot de passe');
  }
}

/**
 * Génère un token JWT sécurisé
 * @param {object} payload - Données à inclure dans le token
 * @param {string} secret - Clé secrète JWT
 * @param {object} options - Options JWT
 * @returns {string} Token JWT
 */
function generateJWT(payload, secret, options = {}) {
  const defaultOptions = {
    expiresIn: '8h',
    issuer: 'dictionnaire-zarma-api',
    audience: 'dictionnaire-zarma-client'
  };
  
  return jwt.sign(payload, secret, { ...defaultOptions, ...options });
}

/**
 * Vérifie et décode un token JWT
 * @param {string} token - Token à vérifier
 * @param {string} secret - Clé secrète JWT
 * @returns {object} Payload décodé
 */
function verifyJWT(token, secret) {
  try {
    return jwt.verify(token, secret, {
      issuer: 'dictionnaire-zarma-api',
      audience: 'dictionnaire-zarma-client'
    });
  } catch (error) {
    throw new Error('Token JWT invalide');
  }
}

/**
 * Valide la force d'un mot de passe
 * @param {string} password - Mot de passe à valider
 * @returns {object} Résultat de la validation
 */
function validatePasswordStrength(password) {
  const result = {
    isValid: false,
    score: 0,
    issues: []
  };

  if (!password) {
    result.issues.push('Le mot de passe est requis');
    return result;
  }

  // Longueur minimale
  if (password.length < 8) {
    result.issues.push('Le mot de passe doit faire au moins 8 caractères');
  } else {
    result.score += 1;
  }

  // Contient des minuscules
  if (/[a-z]/.test(password)) {
    result.score += 1;
  } else {
    result.issues.push('Le mot de passe doit contenir au moins une lettre minuscule');
  }

  // Contient des majuscules
  if (/[A-Z]/.test(password)) {
    result.score += 1;
  } else {
    result.issues.push('Le mot de passe doit contenir au moins une lettre majuscule');
  }

  // Contient des chiffres
  if (/\d/.test(password)) {
    result.score += 1;
  } else {
    result.issues.push('Le mot de passe doit contenir au moins un chiffre');
  }

  // Contient des caractères spéciaux
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    result.score += 1;
  } else {
    result.issues.push('Le mot de passe doit contenir au moins un caractère spécial');
  }

  // Le mot de passe est valide s'il a un score d'au moins 3/5
  result.isValid = result.score >= 3 && result.issues.length === 0;

  return result;
}

/**
 * Nettoie et valide une entrée utilisateur
 * @param {string} input - Entrée à nettoyer
 * @param {object} options - Options de nettoyage
 * @returns {string} Entrée nettoyée
 */
function sanitizeInput(input, options = {}) {
  if (typeof input !== 'string') {
    return '';
  }

  let cleaned = input.trim();

  // Supprimer les caractères de contrôle
  cleaned = cleaned.replace(/[\x00-\x1F\x7F]/g, '');

  // Échapper les caractères HTML si demandé
  if (options.escapeHtml) {
    cleaned = cleaned
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  // Limiter la longueur si spécifié
  if (options.maxLength && cleaned.length > options.maxLength) {
    cleaned = cleaned.substring(0, options.maxLength);
  }

  return cleaned;
}

/**
 * Génère un identifiant de session sécurisé
 * @returns {string} ID de session
 */
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Crée un hash sécurisé pour les tokens de session
 * @param {string} token - Token à hacher
 * @returns {string} Hash du token
 */
function hashSessionToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Valide un nom d'utilisateur
 * @param {string} username - Nom d'utilisateur à valider
 * @returns {object} Résultat de la validation
 */
function validateUsername(username) {
  const result = {
    isValid: false,
    issues: []
  };

  if (!username) {
    result.issues.push('Le nom d\'utilisateur est requis');
    return result;
  }

  // Longueur
  if (username.length < 3) {
    result.issues.push('Le nom d\'utilisateur doit faire au moins 3 caractères');
  }
  
  if (username.length > 50) {
    result.issues.push('Le nom d\'utilisateur ne peut pas dépasser 50 caractères');
  }

  // Caractères autorisés (lettres, chiffres, underscore, tiret)
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    result.issues.push('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores');
  }

  // Ne peut pas commencer par un chiffre
  if (/^\d/.test(username)) {
    result.issues.push('Le nom d\'utilisateur ne peut pas commencer par un chiffre');
  }

  result.isValid = result.issues.length === 0;
  return result;
}

/**
 * Valide une adresse email
 * @param {string} email - Email à valider
 * @returns {object} Résultat de la validation
 */
function validateEmail(email) {
  const result = {
    isValid: false,
    issues: []
  };

  if (!email) {
    result.issues.push('L\'adresse email est requise');
    return result;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    result.issues.push('L\'adresse email n\'est pas valide');
  }

  if (email.length > 255) {
    result.issues.push('L\'adresse email ne peut pas dépasser 255 caractères');
  }

  result.isValid = result.issues.length === 0;
  return result;
}

/**
 * Génère un code de vérification numérique
 * @param {number} length - Longueur du code
 * @returns {string} Code de vérification
 */
function generateVerificationCode(length = 6) {
  let code = '';
  for (let i = 0; i < length; i++) {
    code += Math.floor(Math.random() * 10).toString();
  }
  return code;
}

/**
 * Calcule le temps jusqu'à expiration en secondes
 * @param {number} expiresAt - Timestamp d'expiration
 * @returns {number} Secondes jusqu'à expiration
 */
function getTimeUntilExpiration(expiresAt) {
  return Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
}

/**
 * Détecte les tentatives d'injection SQL basiques
 * @param {string} input - Entrée à vérifier
 * @returns {boolean} True si une injection est détectée
 */
function detectSQLInjection(input) {
  if (typeof input !== 'string') return false;
  
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
    /(--|\*\/|\*|\/\*)/,
    /(\b(OR|AND)\b.*=.*=)/i,
    /('|(\\x27)|(\\x2D)|(\\x2D\\x2D))/i
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
}

/**
 * Détecte les tentatives XSS basiques
 * @param {string} input - Entrée à vérifier
 * @returns {boolean} True si du XSS est détecté
 */
function detectXSS(input) {
  if (typeof input !== 'string') return false;
  
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<img[^>]*src\s*=\s*["']javascript:/gi
  ];
  
  return xssPatterns.some(pattern => pattern.test(input));
}

/**
 * Rate limiter en mémoire simple
 */
class MemoryRateLimiter {
  constructor() {
    this.requests = new Map();
    this.cleanup();
  }

  /**
   * Vérifie si une requête est autorisée
   * @param {string} key - Clé unique (IP, user ID, etc.)
   * @param {number} limit - Nombre maximum de requêtes
   * @param {number} windowMs - Fenêtre de temps en ms
   * @returns {object} Résultat avec isAllowed et informations
   */
  check(key, limit, windowMs) {
    const now = Date.now();
    const windowStart = now - windowMs;

    // Récupérer ou créer l'entrée pour cette clé
    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }

    const requests = this.requests.get(key);
    
    // Supprimer les requêtes anciennes
    const validRequests = requests.filter(time => time > windowStart);
    this.requests.set(key, validRequests);

    // Vérifier si la limite est dépassée
    if (validRequests.length >= limit) {
      return {
        isAllowed: false,
        remaining: 0,
        resetTime: Math.min(...validRequests) + windowMs,
        totalHits: validRequests.length
      };
    }

    // Ajouter cette requête
    validRequests.push(now);
    this.requests.set(key, validRequests);

    return {
      isAllowed: true,
      remaining: limit - validRequests.length,
      resetTime: now + windowMs,
      totalHits: validRequests.length
    };
  }

  /**
   * Nettoie périodiquement les anciennes entrées
   */
  cleanup() {
    setInterval(() => {
      const now = Date.now();
      const maxAge = 24 * 60 * 60 * 1000; // 24 heures

      for (const [key, requests] of this.requests.entries()) {
        const validRequests = requests.filter(time => now - time < maxAge);
        if (validRequests.length === 0) {
          this.requests.delete(key);
        } else {
          this.requests.set(key, validRequests);
        }
      }
    }, 60 * 60 * 1000); // Nettoyer toutes les heures
  }

  /**
   * Réinitialise le compteur pour une clé
   * @param {string} key - Clé à réinitialiser
   */
  reset(key) {
    this.requests.delete(key);
  }

  /**
   * Obtient les statistiques pour une clé
   * @param {string} key - Clé à vérifier
   * @returns {object} Statistiques
   */
  getStats(key) {
    const requests = this.requests.get(key) || [];
    const now = Date.now();
    
    return {
      totalRequests: requests.length,
      requestsLastHour: requests.filter(time => now - time < 60 * 60 * 1000).length,
      requestsLastDay: requests.filter(time => now - time < 24 * 60 * 60 * 1000).length,
      firstRequest: requests.length > 0 ? Math.min(...requests) : null,
      lastRequest: requests.length > 0 ? Math.max(...requests) : null
    };
  }
}

/**
 * Générateur de mots de passe sécurisés
 * @param {number} length - Longueur du mot de passe
 * @param {object} options - Options de génération
 * @returns {string} Mot de passe généré
 */
function generateSecurePassword(length = 12, options = {}) {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true,
    excludeSimilar = true,
    excludeAmbiguous = true
  } = options;

  let charset = '';
  
  if (includeLowercase) {
    charset += excludeSimilar ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  }
  
  if (includeUppercase) {
    charset += excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  }
  
  if (includeNumbers) {
    charset += excludeSimilar ? '23456789' : '0123456789';
  }
  
  if (includeSymbols) {
    charset += excludeAmbiguous ? '!@#$%^&*+-=' : '!@#$%^&*()_+-=[]{}|;:,.<>?';
  }

  if (charset === '') {
    throw new Error('Au moins un type de caractère doit être inclus');
  }

  let password = '';
  
  // S'assurer qu'au moins un caractère de chaque type requis est inclus
  if (includeLowercase) {
    const lowerChars = excludeSimilar ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    password += lowerChars[crypto.randomInt(lowerChars.length)];
  }
  
  if (includeUppercase) {
    const upperChars = excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    password += upperChars[crypto.randomInt(upperChars.length)];
  }
  
  if (includeNumbers) {
    const numberChars = excludeSimilar ? '23456789' : '0123456789';
    password += numberChars[crypto.randomInt(numberChars.length)];
  }
  
  if (includeSymbols) {
    const symbolChars = excludeAmbiguous ? '!@#$%^&*+-=' : '!@#$%^&*()_+-=[]{}|;:,.<>?';
    password += symbolChars[crypto.randomInt(symbolChars.length)];
  }

  // Compléter avec des caractères aléatoires
  for (let i = password.length; i < length; i++) {
    password += charset[crypto.randomInt(charset.length)];
  }

  // Mélanger le mot de passe pour éviter les patterns prévisibles
  return password.split('').sort(() => crypto.randomInt(3) - 1).join('');
}

/**
 * Vérifie si une IP est dans une liste de blocage
 * @param {string} ip - Adresse IP à vérifier
 * @param {Array} blacklist - Liste des IP bloquées
 * @returns {boolean} True si l'IP est bloquée
 */
function isIPBlocked(ip, blacklist = []) {
  if (!ip) return false;
  
  // Vérifier les IP exactes
  if (blacklist.includes(ip)) return true;
  
  // Vérifier les plages d'IP (format CIDR basique)
  for (const blockedRange of blacklist) {
    if (blockedRange.includes('/')) {
      const [network, prefixLength] = blockedRange.split('/');
      if (isIPInRange(ip, network, parseInt(prefixLength))) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Vérifie si une IP est dans une plage CIDR (IPv4 seulement)
 * @param {string} ip - IP à tester
 * @param {string} network - Réseau de base
 * @param {number} prefixLength - Longueur du préfixe
 * @returns {boolean} True si l'IP est dans la plage
 */
function isIPInRange(ip, network, prefixLength) {
  const ipToInt = (ip) => {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  };
  
  const ipInt = ipToInt(ip);
  const networkInt = ipToInt(network);
  const mask = (0xffffffff << (32 - prefixLength)) >>> 0;
  
  return (ipInt & mask) === (networkInt & mask);
}

// Export des fonctions
module.exports = {
  generateSecureToken,
  generateSalt,
  hashPassword,
  verifyPassword,
  generateJWT,
  verifyJWT,
  validatePasswordStrength,
  sanitizeInput,
  generateSessionId,
  hashSessionToken,
  validateUsername,
  validateEmail,
  generateVerificationCode,
  getTimeUntilExpiration,
  detectSQLInjection,
  detectXSS,
  MemoryRateLimiter,
  generateSecurePassword,
  isIPBlocked,
  isIPInRange
};