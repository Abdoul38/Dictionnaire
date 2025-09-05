// middleware/logger.js - Système de logs pour le Dictionnaire Zarma
const fs = require('fs');
const path = require('path');

/**
 * Niveaux de log
 */
const LogLevel = {
  ERROR: 'ERROR',
  WARN: 'WARN',
  INFO: 'INFO',
  DEBUG: 'DEBUG'
};

/**
 * Classe Logger pour gérer les logs
 */
class Logger {
  constructor(options = {}) {
    this.logLevel = options.logLevel || LogLevel.INFO;
    this.logFile = options.logFile || path.join(process.cwd(), 'logs', 'app.log');
    this.maxFileSize = options.maxFileSize || 10 * 1024 * 1024; // 10MB
    this.maxFiles = options.maxFiles || 5;
    this.enableConsole = options.enableConsole !== false;
    
    // Créer le dossier de logs s'il n'existe pas
    const logDir = path.dirname(this.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  /**
   * Formate un message de log
   * @param {string} level - Niveau du log
   * @param {string} message - Message à logger
   * @param {object} meta - Métadonnées additionnelles
   * @returns {string} Message formaté
   */
  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const metaString = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level}: ${message}${metaString}`;
  }

  /**
   * Écrit un log dans le fichier
   * @param {string} formattedMessage - Message formaté
   */
  writeToFile(formattedMessage) {
    try {
      // Vérifier la taille du fichier et effectuer la rotation si nécessaire
      if (fs.existsSync(this.logFile)) {
        const stats = fs.statSync(this.logFile);
        if (stats.size > this.maxFileSize) {
          this.rotateLogFile();
        }
      }

      fs.appendFileSync(this.logFile, formattedMessage + '\n');
    } catch (error) {
      if (this.enableConsole) {
        console.error('Erreur lors de l\'écriture du log:', error.message);
      }
    }
  }

  /**
   * Effectue la rotation des fichiers de log
   */
  rotateLogFile() {
    try {
      for (let i = this.maxFiles - 1; i > 0; i--) {
        const oldFile = `${this.logFile}.${i}`;
        const newFile = `${this.logFile}.${i + 1}`;
        
        if (fs.existsSync(oldFile)) {
          if (i === this.maxFiles - 1) {
            fs.unlinkSync(oldFile); // Supprimer le plus ancien
          } else {
            fs.renameSync(oldFile, newFile);
          }
        }
      }

      // Renommer le fichier actuel
      if (fs.existsSync(this.logFile)) {
        fs.renameSync(this.logFile, `${this.logFile}.1`);
      }
    } catch (error) {
      if (this.enableConsole) {
        console.error('Erreur lors de la rotation des logs:', error.message);
      }
    }
  }

  /**
   * Vérifie si un niveau de log doit être enregistré
   * @param {string} level - Niveau à vérifier
   * @returns {boolean} True si le niveau doit être enregistré
   */
  shouldLog(level) {
    const levels = [LogLevel.ERROR, LogLevel.WARN, LogLevel.INFO, LogLevel.DEBUG];
    const currentIndex = levels.indexOf(this.logLevel);
    const messageIndex = levels.indexOf(level);
    return messageIndex <= currentIndex;
  }

  /**
   * Log un message d'erreur
   * @param {string} message - Message d'erreur
   * @param {object} meta - Métadonnées
   */
  error(message, meta = {}) {
    if (this.shouldLog(LogLevel.ERROR)) {
      const formatted = this.formatMessage(LogLevel.ERROR, message, meta);
      this.writeToFile(formatted);
      if (this.enableConsole) {
        console.error(formatted);
      }
    }
  }

  /**
   * Log un message d'avertissement
   * @param {string} message - Message d'avertissement
   * @param {object} meta - Métadonnées
   */
  warn(message, meta = {}) {
    if (this.shouldLog(LogLevel.WARN)) {
      const formatted = this.formatMessage(LogLevel.WARN, message, meta);
      this.writeToFile(formatted);
      if (this.enableConsole) {
        console.warn(formatted);
      }
    }
  }

  /**
   * Log un message informatif
   * @param {string} message - Message informatif
   * @param {object} meta - Métadonnées
   */
  info(message, meta = {}) {
    if (this.shouldLog(LogLevel.INFO)) {
      const formatted = this.formatMessage(LogLevel.INFO, message, meta);
      this.writeToFile(formatted);
      if (this.enableConsole) {
        console.log(formatted);
      }
    }
  }

  /**
   * Log un message de debug
   * @param {string} message - Message de debug
   * @param {object} meta - Métadonnées
   */
  debug(message, meta = {}) {
    if (this.shouldLog(LogLevel.DEBUG)) {
      const formatted = this.formatMessage(LogLevel.DEBUG, message, meta);
      this.writeToFile(formatted);
      if (this.enableConsole && process.env.NODE_ENV === 'development') {
        console.log(formatted);
      }
    }
  }
}

/**
 * Instance globale du logger
 */
const logger = new Logger({
  logLevel: process.env.LOG_LEVEL || LogLevel.INFO,
  logFile: process.env.LOG_FILE || path.join(process.cwd(), 'logs', 'app.log'),
  enableConsole: process.env.NODE_ENV !== 'production'
});

/**
 * Middleware pour logger les requêtes HTTP
 * @param {object} req - Objet requête Express
 * @param {object} res - Objet réponse Express
 * @param {function} next - Fonction next d'Express
 */
function requestLogger(req, res, next) {
  const start = Date.now();
  const originalSend = res.send;

  // Capturer la réponse
  res.send = function(data) {
    const duration = Date.now() - start;
    const statusCode = res.statusCode;
    const method = req.method;
    const url = req.originalUrl || req.url;
    const userAgent = req.get('User-Agent') || '';
    const ip = req.ip || req.connection.remoteAddress || '';
    const contentLength = res.get('Content-Length') || 0;

    // Déterminer le niveau de log selon le status code
    let logLevel;
    if (statusCode >= 500) {
      logLevel = 'error';
    } else if (statusCode >= 400) {
      logLevel = 'warn';
    } else {
      logLevel = 'info';
    }

    // Créer le message de log
    const message = `${method} ${url} ${statusCode} ${duration}ms`;
    const meta = {
      method,
      url,
      statusCode,
      duration,
      ip,
      userAgent,
      contentLength: parseInt(contentLength) || 0,
      timestamp: new Date().toISOString()
    };

    // Ajouter des informations d'authentification si disponibles
    if (req.user) {
      meta.userId = req.user.userId;
      meta.username = req.user.username;
    }

    // Logger selon le niveau approprié
    logger[logLevel](message, meta);

    // Appeler la méthode send originale
    originalSend.call(this, data);
  };

  next();
}

/**
 * Middleware pour logger les erreurs
 * @param {Error} err - Erreur à logger
 * @param {object} req - Objet requête Express
 * @param {object} res - Objet réponse Express
 * @param {function} next - Fonction next d'Express
 */
function errorLogger(err, req, res, next) {
  const method = req.method;
  const url = req.originalUrl || req.url;
  const ip = req.ip || req.connection.remoteAddress || '';
  const userAgent = req.get('User-Agent') || '';

  const message = `Erreur lors du traitement de ${method} ${url}`;
  const meta = {
    error: {
      name: err.name,
      message: err.message,
      stack: err.stack
    },
    request: {
      method,
      url,
      ip,
      userAgent,
      body: req.body,
      params: req.params,
      query: req.query
    }
  };

  // Ajouter des informations d'authentification si disponibles
  if (req.user) {
    meta.request.userId = req.user.userId;
    meta.request.username = req.user.username;
  }

  logger.error(message, meta);
  next(err);
}

/**
 * Logger spécialisé pour les événements de sécurité
 */
class SecurityLogger {
  /**
   * Log une tentative de connexion
   * @param {string} username - Nom d'utilisateur
   * @param {string} ip - Adresse IP
   * @param {boolean} success - Succès de la connexion
   * @param {string} reason - Raison de l'échec si applicable
   */
  static loginAttempt(username, ip, success, reason = null) {
    const message = success ? 
      `Connexion réussie pour ${username}` : 
      `Échec de connexion pour ${username}`;
    
    const meta = {
      event: 'login_attempt',
      username,
      ip,
      success,
      reason,
      timestamp: new Date().toISOString()
    };

    if (success) {
      logger.info(message, meta);
    } else {
      logger.warn(message, meta);
    }
  }

  /**
   * Log un changement de mot de passe
   * @param {string} username - Nom d'utilisateur
   * @param {string} ip - Adresse IP
   * @param {boolean} success - Succès du changement
   */
  static passwordChange(username, ip, success) {
    const message = success ? 
      `Mot de passe changé avec succès pour ${username}` : 
      `Échec du changement de mot de passe pour ${username}`;
    
    const meta = {
      event: 'password_change',
      username,
      ip,
      success,
      timestamp: new Date().toISOString()
    };

    logger.info(message, meta);
  }

  /**
   * Log une tentative d'accès non autorisé
   * @param {string} resource - Ressource demandée
   * @param {string} ip - Adresse IP
   * @param {string} reason - Raison du refus
   */
  static unauthorizedAccess(resource, ip, reason) {
    const message = `Tentative d'accès non autorisé à ${resource}`;
    
    const meta = {
      event: 'unauthorized_access',
      resource,
      ip,
      reason,
      timestamp: new Date().toISOString()
    };

    logger.warn(message, meta);
  }

  /**
   * Log une activité suspecte
   * @param {string} activity - Description de l'activité
   * @param {string} ip - Adresse IP
   * @param {object} details - Détails supplémentaires
   */
  static suspiciousActivity(activity, ip, details = {}) {
    const message = `Activité suspecte détectée: ${activity}`;
    
    const meta = {
      event: 'suspicious_activity',
      activity,
      ip,
      details,
      timestamp: new Date().toISOString()
    };

    logger.warn(message, meta);
  }

  /**
   * Log un dépassement de rate limit
   * @param {string} ip - Adresse IP
   * @param {string} endpoint - Endpoint concerné
   * @param {number} attempts - Nombre de tentatives
   */
  static rateLimitExceeded(ip, endpoint, attempts) {
    const message = `Rate limit dépassé pour ${ip} sur ${endpoint}`;
    
    const meta = {
      event: 'rate_limit_exceeded',
      ip,
      endpoint,
      attempts,
      timestamp: new Date().toISOString()
    };

    logger.warn(message, meta);
  }
}

/**
 * Collecteur de métriques système
 */
class MetricsCollector {
  constructor() {
    this.metrics = {
      requests: {
        total: 0,
        by_method: {},
        by_status: {},
        by_endpoint: {}
      },
      errors: {
        total: 0,
        by_type: {}
      },
      auth: {
        login_attempts: 0,
        successful_logins: 0,
        failed_logins: 0
      },
      performance: {
        avg_response_time: 0,
        response_times: []
      }
    };

    // Nettoyer les métriques périodiquement
    setInterval(() => {
      this.cleanup();
    }, 60 * 60 * 1000); // Toutes les heures
  }

  /**
   * Enregistre une requête
   * @param {object} req - Requête Express
   * @param {object} res - Réponse Express
   * @param {number} responseTime - Temps de réponse en ms
   */
  recordRequest(req, res, responseTime) {
    this.metrics.requests.total++;
    
    // Par méthode
    const method = req.method;
    this.metrics.requests.by_method[method] = (this.metrics.requests.by_method[method] || 0) + 1;
    
    // Par status
    const status = res.statusCode;
    this.metrics.requests.by_status[status] = (this.metrics.requests.by_status[status] || 0) + 1;
    
    // Par endpoint (simplifier l'URL)
    const endpoint = req.route ? req.route.path : req.path;
    this.metrics.requests.by_endpoint[endpoint] = (this.metrics.requests.by_endpoint[endpoint] || 0) + 1;
    
    // Temps de réponse
    this.metrics.performance.response_times.push(responseTime);
    if (this.metrics.performance.response_times.length > 1000) {
      this.metrics.performance.response_times = this.metrics.performance.response_times.slice(-1000);
    }
    
    // Calculer la moyenne
    const sum = this.metrics.performance.response_times.reduce((a, b) => a + b, 0);
    this.metrics.performance.avg_response_time = sum / this.metrics.performance.response_times.length;
  }

  /**
   * Enregistre une erreur
   * @param {Error} error - Erreur à enregistrer
   */
  recordError(error) {
    this.metrics.errors.total++;
    const errorType = error.name || 'Unknown';
    this.metrics.errors.by_type[errorType] = (this.metrics.errors.by_type[errorType] || 0) + 1;
  }

  /**
   * Enregistre une tentative d'authentification
   * @param {boolean} success - Succès de l'authentification
   */
  recordAuthAttempt(success) {
    this.metrics.auth.login_attempts++;
    if (success) {
      this.metrics.auth.successful_logins++;
    } else {
      this.metrics.auth.failed_logins++;
    }
  }

  /**
   * Obtient les métriques actuelles
   * @returns {object} Métriques
   */
  getMetrics() {
    return { ...this.metrics };
  }

  /**
   * Nettoie les anciennes données
   */
  cleanup() {
    // Garder seulement les 1000 derniers temps de réponse
    if (this.metrics.performance.response_times.length > 1000) {
      this.metrics.performance.response_times = this.metrics.performance.response_times.slice(-1000);
    }
  }

  /**
   * Remet à zéro les métriques
   */
  reset() {
    this.metrics = {
      requests: {
        total: 0,
        by_method: {},
        by_status: {},
        by_endpoint: {}
      },
      errors: {
        total: 0,
        by_type: {}
      },
      auth: {
        login_attempts: 0,
        successful_logins: 0,
        failed_logins: 0
      },
      performance: {
        avg_response_time: 0,
        response_times: []
      }
    };
  }
}

// Instance globale du collecteur de métriques
const metricsCollector = new MetricsCollector();

/**
 * Middleware pour collecter les métriques
 */
function metricsMiddleware(req, res, next) {
  const start = Date.now();
  const originalSend = res.send;

  res.send = function(data) {
    const responseTime = Date.now() - start;
    metricsCollector.recordRequest(req, res, responseTime);
    originalSend.call(this, data);
  };

  next();
}

module.exports = {
  Logger,
  LogLevel,
  logger,
  requestLogger,
  errorLogger,
  SecurityLogger,
  MetricsCollector,
  metricsCollector,
  metricsMiddleware
};