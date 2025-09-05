// server.js - Backend API pour le Dictionnaire Zarma avec Authentification
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration sécurisée
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const ADMIN_SESSION_DURATION = '8h';
const REMEMBER_SESSION_DURATION = '30d';

// Middleware de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));
// Route de test simple
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://172.18.2.199:3000', 
    'http://192.168.1.1:3000',  // Ajoutez votre réseau local
    'http://192.168.0.1:3000',  // Ajoutez d'autres adresses possibles
    'capacitor://localhost',    // Pour Capacitor
    'http://localhost',         // Pour les apps mobiles
    'http://10.0.2.2:3000',     // Pour l'émulateur Android
    '*'                         // Temporairement pour le debug - À SUPPRIMER EN PRODUCTION
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Ajoutez un middleware pour logger les requêtes entrantes
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} from ${req.ip}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', JSON.stringify(req.body, null, 2));
  }
  next();
});

// Améliorez la route de test
app.get('/api/test', (req, res) => {
  console.log('Route de test appelée depuis:', req.ip);
  res.json({
    success: true,
    message: 'API fonctionne!',
    timestamp: new Date().toISOString(),
    server_ip: req.connection.localAddress,
    client_ip: req.ip,
    headers: req.headers
  });
});

// Ajoutez une route de diagnostic réseau
app.get('/api/network-info', (req, res) => {
  const os = require('os');
  const networkInterfaces = os.networkInterfaces();
  
  res.json({
    server_interfaces: networkInterfaces,
    client_ip: req.ip,
    client_headers: req.headers,
    timestamp: new Date().toISOString()
  });
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Configuration Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Rate limiting pour les tentatives de connexion
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 tentatives par IP
  message: {
    error: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.',
    lockoutTime: 15
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting général pour l'API
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requêtes par IP
  message: {
    error: 'Trop de requêtes. Réessayez plus tard.'
  }
});

// Appliquer le rate limiting aux routes API
app.use('/api', apiLimiter);

// Initialisation de la base de données
const dbPath = path.join(__dirname, 'dictionary.db');
const db = new sqlite3.Database(dbPath);

// Création des tables
db.serialize(() => {
  // Table des utilisateurs administrateurs
  db.run(`
    CREATE TABLE IF NOT EXISTS admin_users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'admin',
      is_active BOOLEAN DEFAULT TRUE,
      last_login INTEGER,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      updated_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
  `);

  // Table des sessions
  db.run(`
    CREATE TABLE IF NOT EXISTS admin_sessions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      expires_at INTEGER NOT NULL,
      is_remember_me BOOLEAN DEFAULT FALSE,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
    )
  `);

  // Table des tentatives de connexion
  db.run(`
    CREATE TABLE IF NOT EXISTS login_attempts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT NOT NULL,
      username TEXT,
      success BOOLEAN NOT NULL,
      attempt_time INTEGER DEFAULT (strftime('%s', 'now')),
      user_agent TEXT
    )
  `);

  // Table principale des mots
  db.run(`
    CREATE TABLE IF NOT EXISTS words(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      zarma_word TEXT NOT NULL,
      zarma_example TEXT NOT NULL,
      french_meaning TEXT NOT NULL,
      french_example TEXT NOT NULL,
      category TEXT,
      pronunciation TEXT,
      difficulty_level INTEGER DEFAULT 1,
      etymology TEXT,
      synonyms TEXT,
      antonyms TEXT,
      related_words TEXT,
      usage_frequency INTEGER DEFAULT 0,
      audio_path TEXT,
      image_path TEXT,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      updated_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
  `);

  // Table des favoris
  db.run(`
    CREATE TABLE IF NOT EXISTS favorites(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      word_id INTEGER NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (word_id) REFERENCES words(id) ON DELETE CASCADE
    )
  `);

  // Table des progrès d'apprentissage
  db.run(`
    CREATE TABLE IF NOT EXISTS learning_progress(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      word_id INTEGER NOT NULL,
      view_count INTEGER DEFAULT 0,
      practice_count INTEGER DEFAULT 0,
      correct_answers INTEGER DEFAULT 0,
      wrong_answers INTEGER DEFAULT 0,
      is_learned BOOLEAN DEFAULT FALSE,
      last_practiced INTEGER,
      learning_streak INTEGER DEFAULT 0,
      difficulty_adjustment REAL DEFAULT 1.0,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      updated_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (word_id) REFERENCES words(id) ON DELETE CASCADE
    )
  `);

  // Table des notes utilisateur
  db.run(`
    CREATE TABLE IF NOT EXISTS user_notes(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      word_id INTEGER NOT NULL,
      note_text TEXT NOT NULL,
      tags TEXT,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      updated_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (word_id) REFERENCES words(id) ON DELETE CASCADE
    )
  `);

  // Table des statistiques d'utilisation
  db.run(`
    CREATE TABLE IF NOT EXISTS usage_stats(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL,
      words_studied INTEGER DEFAULT 0,
      time_spent INTEGER DEFAULT 0,
      quiz_completed INTEGER DEFAULT 0,
      new_words_learned INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
  `);

  // Index pour améliorer les performances
  db.run('CREATE INDEX IF NOT EXISTS idx_words_zarma ON words(zarma_word)');
  db.run('CREATE INDEX IF NOT EXISTS idx_words_french ON words(french_meaning)');
  db.run('CREATE INDEX IF NOT EXISTS idx_words_category ON words(category)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token_hash)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)');

  // Créer un utilisateur admin par défaut
  createDefaultAdmin();
});

// Création de l'administrateur par défaut
async function createDefaultAdmin() {
  const defaultUsername = 'admin';
  const defaultPassword = 'admin123'; // CHANGEZ CECI EN PRODUCTION !

  db.get('SELECT id FROM admin_users WHERE username = ?', [defaultUsername], async (err, row) => {
    if (err) {
      console.error('Erreur lors de la vérification de l\'admin:', err);
      return;
    }

    if (!row) {
      try {
        const passwordHash = await bcrypt.hash(defaultPassword, 12);
        
        db.run(
          'INSERT INTO admin_users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
          [defaultUsername, passwordHash, 'admin@dictionnaire-zarma.com', 'super_admin'],
          function(err) {
            if (err) {
              console.error('Erreur lors de la création de l\'admin:', err);
            } else {
              console.log('👤 Administrateur par défaut créé:');
              console.log('   Utilisateur: admin');
              console.log('   Mot de passe: admin123');
              console.log('   ⚠️  CHANGEZ CES IDENTIFIANTS EN PRODUCTION !');
            }
          }
        );
      } catch (error) {
        console.error('Erreur lors du hachage du mot de passe:', error);
      }
    }
  });
}

// Fonctions utilitaires
const parseCommaSeparated = (str) => {
  if (!str) return [];
  return str.split(',').map(s => s.trim()).filter(s => s.length > 0);
};

const joinCommaSeparated = (arr) => {
  if (!Array.isArray(arr)) return '';
  return arr.filter(s => s && s.trim()).join(',');
};

// Middleware d'authentification
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: 'Token d\'accès requis',
      code: 'MISSING_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Vérifier si la session existe toujours
    db.get(
      `SELECT s.*, u.username, u.is_active, u.role 
       FROM admin_sessions s 
       JOIN admin_users u ON s.user_id = u.id 
       WHERE s.user_id = ? AND s.expires_at > ? AND u.is_active = TRUE 
       ORDER BY s.created_at DESC LIMIT 1`,
      [decoded.userId, Math.floor(Date.now() / 1000)],
      (err, session) => {
        if (err) {
          console.error('Erreur lors de la vérification de session:', err);
          return res.status(500).json({ 
            error: 'Erreur interne du serveur',
            code: 'SERVER_ERROR'
          });
        }

        if (!session) {
          return res.status(401).json({ 
            error: 'Session expirée ou invalide',
            code: 'INVALID_SESSION'
          });
        }

        req.user = {
          userId: decoded.userId,
          username: decoded.username,
          role: decoded.role
        };
        req.session = session;
        next();
      }
    );
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expiré',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({ 
      error: 'Token invalide',
      code: 'INVALID_TOKEN'
    });
  }
}

// Validation middleware
const validateWord = [
  body('zarmaWord').notEmpty().withMessage('Le mot zarma est requis'),
  body('frenchMeaning').notEmpty().withMessage('La signification française est requise'),
  body('zarmaExample').notEmpty().withMessage('L\'exemple zarma est requis'),
  body('frenchExample').notEmpty().withMessage('L\'exemple français est requis'),
  body('difficultyLevel').optional().isInt({ min: 1, max: 4 }).withMessage('Le niveau de difficulté doit être entre 1 et 4')
];

// Routes d'authentification

// Route de connexion
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password, rememberMe } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  // Validation des entrées
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Nom d\'utilisateur et mot de passe requis'
    });
  }

  try {
    // Recherche de l'utilisateur
    db.get(
      'SELECT * FROM admin_users WHERE username = ? AND is_active = TRUE',
      [username],
      async (err, user) => {
        if (err) {
          console.error('Erreur DB lors de la connexion:', err);
          return res.status(500).json({
            success: false,
            message: 'Erreur interne du serveur'
          });
        }

        let loginSuccess = false;

        if (user && await bcrypt.compare(password, user.password_hash)) {
          loginSuccess = true;

          try {
            // Générer le token JWT
            const tokenPayload = {
              userId: user.id,
              username: user.username,
              role: user.role
            };

            const sessionDuration = rememberMe ? REMEMBER_SESSION_DURATION : ADMIN_SESSION_DURATION;
            const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: sessionDuration });
            
            // Calculer la date d'expiration en secondes
            const expirationSeconds = rememberMe ? 30 * 24 * 60 * 60 : 8 * 60 * 60;
            const expiresAt = Math.floor(Date.now() / 1000) + expirationSeconds;
            
            // Nettoyer les anciennes sessions expirées
            db.run('DELETE FROM admin_sessions WHERE expires_at < ?', [Math.floor(Date.now() / 1000)]);
            
            // Stocker la session dans la base
            db.run(
              'INSERT INTO admin_sessions (user_id, token_hash, ip_address, user_agent, expires_at, is_remember_me) VALUES (?, ?, ?, ?, ?, ?)',
              [user.id, token.substring(0, 50), ipAddress, userAgent, expiresAt, rememberMe ? 1 : 0],
              function(err) {
                if (err) {
                  console.error('Erreur lors de la création de session:', err);
                  return res.status(500).json({
                    success: false,
                    message: 'Erreur lors de la création de session'
                  });
                }

                // Mettre à jour la dernière connexion
                db.run('UPDATE admin_users SET last_login = strftime(\'%s\', \'now\') WHERE id = ?', [user.id]);

                // Retourner la réponse de succès
                res.json({
                  success: true,
                  message: 'Connexion réussie',
                  token: token,
                  user: {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    email: user.email
                  },
                  expiresIn: sessionDuration,
                  expiresAt: expiresAt
                });
              }
            );
          } catch (tokenError) {
            console.error('Erreur lors de la génération du token:', tokenError);
            return res.status(500).json({
              success: false,
              message: 'Erreur lors de la création du token'
            });
          }
        } else {
          // Connexion échouée
          res.status(401).json({
            success: false,
            message: 'Identifiants incorrects'
          });
        }

        // Enregistrer la tentative de connexion
        db.run(
          'INSERT INTO login_attempts (ip_address, username, success, user_agent) VALUES (?, ?, ?, ?)',
          [ipAddress, username, loginSuccess ? 1 : 0, userAgent],
          (err) => {
            if (err) {
              console.error('Erreur lors de l\'enregistrement de la tentative:', err);
            }
          }
        );
      }
    );
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur interne du serveur'
    });
  }
});

// Route de déconnexion
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  // Supprimer toutes les sessions de l'utilisateur
  db.run('DELETE FROM admin_sessions WHERE user_id = ?', [userId], (err) => {
    if (err) {
      console.error('Erreur lors de la déconnexion:', err);
      return res.status(500).json({
        success: false,
        message: 'Erreur lors de la déconnexion'
      });
    }
    
    res.json({
      success: true,
      message: 'Déconnexion réussie'
    });
  });
});

// Route de vérification du token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.userId,
      username: req.user.username,
      role: req.user.role
    }
  });
});

// Route pour changer le mot de passe
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.userId;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: 'Mot de passe actuel et nouveau mot de passe requis'
    });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Le nouveau mot de passe doit faire au moins 6 caractères'
    });
  }

  try {
    // Vérifier le mot de passe actuel
    db.get('SELECT password_hash FROM admin_users WHERE id = ?', [userId], async (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          success: false,
          message: 'Utilisateur non trouvé'
        });
      }

      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
      
      if (!isCurrentPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'Mot de passe actuel incorrect'
        });
      }

      // Hacher le nouveau mot de passe
      const newPasswordHash = await bcrypt.hash(newPassword, 12);

      // Mettre à jour le mot de passe
      db.run(
        'UPDATE admin_users SET password_hash = ?, updated_at = strftime(\'%s\', \'now\') WHERE id = ?',
        [newPasswordHash, userId],
        function(err) {
          if (err) {
            console.error('Erreur lors du changement de mot de passe:', err);
            return res.status(500).json({
              success: false,
              message: 'Erreur lors du changement de mot de passe'
            });
          }

          // Supprimer toutes les autres sessions
          db.run('DELETE FROM admin_sessions WHERE user_id = ? AND token_hash != ?', 
            [userId, req.session.token_hash]);

          res.json({
            success: true,
            message: 'Mot de passe changé avec succès'
          });
        }
      );
    });
  } catch (error) {
    console.error('Erreur lors du changement de mot de passe:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur interne du serveur'
    });
  }
});

// Routes API protégées

// GET /api/words - Récupérer tous les mots avec filtres optionnels
app.get('/api/words', (req, res) => {
  const { search, category, difficulty, limit, offset } = req.query;
  
  let query = `
    SELECT w.*, 
           lp.view_count, lp.practice_count, lp.is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE 1=1
  `;
  
  const params = [];
  
  if (search) {
    query += ` AND (w.zarma_word LIKE ? OR w.french_meaning LIKE ? OR w.zarma_example LIKE ? OR w.french_example LIKE ?)`;
    const searchParam = `%${search}%`;
    params.push(searchParam, searchParam, searchParam, searchParam);
  }
  
  if (category) {
    query += ` AND w.category = ?`;
    params.push(category);
  }
  
  if (difficulty) {
    query += ` AND w.difficulty_level = ?`;
    params.push(difficulty);
  }
  
  query += ` ORDER BY w.usage_frequency DESC, w.zarma_word ASC`;
  
  if (limit) {
    query += ` LIMIT ?`;
    params.push(parseInt(limit));
    
    if (offset) {
      query += ` OFFSET ?`;
      params.push(parseInt(offset));
    }
  }
  
  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Erreur lors de la récupération des mots:', err);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    // Transformer les données pour le format attendu
    const words = rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      // Données supplémentaires
      viewCount: row.view_count || 0,
      practiceCount: row.practice_count || 0,
      isLearned: Boolean(row.is_learned),
      isFavorite: Boolean(row.is_favorite)
    }));
    
    res.json({ words, total: words.length });
  });
});

// GET /api/words/:id - Récupérer un mot spécifique
app.get('/api/words/:id', (req, res) => {
  const id = req.params.id;
  
  db.get(`
    SELECT w.*, 
           lp.view_count, lp.practice_count, lp.correct_answers, lp.wrong_answers, 
           lp.is_learned, lp.last_practiced, lp.learning_streak,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE w.id = ?
  `, [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    if (!row) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    const word = {
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      // Données de progression
      viewCount: row.view_count || 0,
      practiceCount: row.practice_count || 0,
      correctAnswers: row.correct_answers || 0,
      wrongAnswers: row.wrong_answers || 0,
      isLearned: Boolean(row.is_learned),
      lastPracticed: row.last_practiced,
      learningStreak: row.learning_streak || 0,
      isFavorite: Boolean(row.is_favorite)
    };
    
    // Incrémenter le compteur de vues
    db.run(`
      INSERT INTO learning_progress (word_id, view_count) 
      VALUES (?, 1) 
      ON CONFLICT(word_id) DO UPDATE SET 
        view_count = view_count + 1,
        updated_at = strftime('%s', 'now')
    `, [id]);
    
    res.json(word);
  });
});

// POST /api/words - Créer un nouveau mot (protégé)
app.post('/api/words', authenticateToken, validateWord, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const {
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel, etymology,
    synonyms, antonyms, relatedWords
  } = req.body;
  
  const query = `
    INSERT INTO words (
      zarma_word, zarma_example, french_meaning, french_example,
      category, pronunciation, difficulty_level, etymology,
      synonyms, antonyms, related_words
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  const params = [
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel || 1, etymology,
    joinCommaSeparated(synonyms),
    joinCommaSeparated(antonyms),
    joinCommaSeparated(relatedWords)
  ];
  
  db.run(query, params, function(err) {
    if (err) {
      console.error('Erreur lors de l\'ajout du mot:', err);
      return res.status(500).json({ error: 'Erreur lors de l\'ajout du mot' });
    }
    
    // Initialiser les progrès d'apprentissage
    db.run(`
      INSERT INTO learning_progress (word_id) VALUES (?)
    `, [this.lastID]);
    
    res.status(201).json({ 
      id: this.lastID, 
      message: 'Mot ajouté avec succès'
    });
  });
});

// PUT /api/words/:id - Modifier un mot existant (protégé)
app.put('/api/words/:id', authenticateToken, validateWord, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const id = req.params.id;
  const {
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel, etymology,
    synonyms, antonyms, relatedWords
  } = req.body;
  
  const query = `
    UPDATE words SET
      zarma_word = ?, zarma_example = ?, french_meaning = ?, french_example = ?,
      category = ?, pronunciation = ?, difficulty_level = ?, etymology = ?,
      synonyms = ?, antonyms = ?, related_words = ?,
      updated_at = strftime('%s', 'now')
    WHERE id = ?
  `;
  
  const params = [
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel || 1, etymology,
    joinCommaSeparated(synonyms),
    joinCommaSeparated(antonyms),
    joinCommaSeparated(relatedWords),
    id
  ];
  
  db.run(query, params, function(err) {
    if (err) {
      console.error('Erreur lors de la modification du mot:', err);
      return res.status(500).json({ error: 'Erreur lors de la modification du mot' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    res.json({ message: 'Mot modifié avec succès' });
  });
});

// DELETE /api/words/:id - Supprimer un mot (protégé)
app.delete('/api/words/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  
  db.run('DELETE FROM words WHERE id = ?', [id], function(err) {
    if (err) {
      console.error('Erreur lors de la suppression du mot:', err);
      return res.status(500).json({ error: 'Erreur lors de la suppression du mot' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    res.json({ message: 'Mot supprimé avec succès' });
  });
});

// GET /api/categories - Récupérer toutes les catégories avec statistiques
app.get('/api/categories', (req, res) => {
  const query = `
    SELECT 
      category,
      COUNT(*) as word_count,
      AVG(difficulty_level) as avg_difficulty,
      SUM(CASE WHEN lp.is_learned = 1 THEN 1 ELSE 0 END) as learned_count
    FROM words w
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE category IS NOT NULL
    GROUP BY category
    ORDER BY word_count DESC
  `;
  
  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    const categories = rows.map(row => ({
      name: row.category,
      wordCount: row.word_count,
      avgDifficulty: Math.round(row.avg_difficulty * 10) / 10,
      learnedCount: row.learned_count || 0,
      progressPercentage: row.word_count > 0 ? Math.round((row.learned_count || 0) / row.word_count * 100) : 0
    }));
    
    res.json(categories);
  });
});

// GET /api/stats - Récupérer les statistiques générales
app.get('/api/stats', (req, res) => {
  const statsQueries = {
    totalWords: 'SELECT COUNT(*) as count FROM words',
    totalCategories: 'SELECT COUNT(DISTINCT category) as count FROM words WHERE category IS NOT NULL',
    avgDifficulty: 'SELECT AVG(difficulty_level) as avg FROM words',
    learnedWords: 'SELECT COUNT(*) as count FROM learning_progress WHERE is_learned = 1',
    totalFavorites: 'SELECT COUNT(*) as count FROM favorites',
    wordsThisWeek: `
      SELECT COUNT(*) as count FROM words 
      WHERE created_at > strftime('%s', 'now', '-7 days')
    `,
    mostViewedWords: `
      SELECT w.zarma_word, w.french_meaning, lp.view_count
      FROM words w
      JOIN learning_progress lp ON w.id = lp.word_id
      ORDER BY lp.view_count DESC
      LIMIT 5
    `,
    categoryDistribution: `
      SELECT category, COUNT(*) as count
      FROM words
      WHERE category IS NOT NULL
      GROUP BY category
      ORDER BY count DESC
    `
  };
  
  const stats = {};
  const promises = Object.keys(statsQueries).map(key => {
    return new Promise((resolve, reject) => {
      db.all(statsQueries[key], [], (err, rows) => {
        if (err) reject(err);
        else {
          if (key === 'mostViewedWords' || key === 'categoryDistribution') {
            stats[key] = rows;
          } else {
            stats[key] = rows[0]?.count !== undefined ? rows[0].count : rows[0]?.avg || 0;
          }
          resolve();
        }
      });
    });
  });
  
  Promise.all(promises)
    .then(() => {
      // Calculer le taux de complétion
      const completionRate = stats.totalWords > 0 ? 
        Math.round((stats.learnedWords / stats.totalWords) * 100) : 0;
      
      res.json({
        ...stats,
        avgDifficulty: Math.round(stats.avgDifficulty * 10) / 10,
        completionRate
      });
    })
    .catch(err => {
      console.error('Erreur lors de la récupération des statistiques:', err);
      res.status(500).json({ error: 'Erreur serveur' });
    });
});

// POST /api/favorites/:wordId - Ajouter/retirer des favoris
app.post('/api/favorites/:wordId', (req, res) => {
  const wordId = req.params.wordId;
  
  // Vérifier si le mot existe
  db.get('SELECT id FROM words WHERE id = ?', [wordId], (err, word) => {
    if (err || !word) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    // Vérifier si déjà en favoris
    db.get('SELECT id FROM favorites WHERE word_id = ?', [wordId], (err, favorite) => {
      if (err) {
        return res.status(500).json({ error: 'Erreur serveur' });
      }
      
      if (favorite) {
        // Retirer des favoris
        db.run('DELETE FROM favorites WHERE word_id = ?', [wordId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
          }
          res.json({ isFavorite: false, message: 'Retiré des favoris' });
        });
      } else {
        // Ajouter aux favoris
        db.run('INSERT INTO favorites (word_id) VALUES (?)', [wordId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
          }
          res.json({ isFavorite: true, message: 'Ajouté aux favoris' });
        });
      }
    });
  });
});

// GET /api/favorites - Récupérer tous les mots favoris
app.get('/api/favorites', (req, res) => {
  const query = `
    SELECT w.*, f.created_at as favorited_at
    FROM words w
    INNER JOIN favorites f ON w.id = f.word_id
    ORDER BY f.created_at DESC
  `;
  
  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    const favorites = rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      favoritedAt: row.favorited_at
    }));
    
    res.json(favorites);
  });
});

// POST /api/progress/:wordId - Mettre à jour les progrès d'apprentissage
app.post('/api/progress/:wordId', (req, res) => {
  const wordId = req.params.wordId;
  const { isCorrect, isLearned } = req.body;
  
  const updateQuery = `
    INSERT INTO learning_progress (
      word_id, practice_count, correct_answers, wrong_answers, 
      is_learned, last_practiced, learning_streak, updated_at
    ) VALUES (?, 1, ?, ?, ?, strftime('%s', 'now'), ?, strftime('%s', 'now'))
    ON CONFLICT(word_id) DO UPDATE SET
      practice_count = practice_count + 1,
      correct_answers = correct_answers + ?,
      wrong_answers = wrong_answers + ?,
      is_learned = COALESCE(?, is_learned),
      last_practiced = strftime('%s', 'now'),
      learning_streak = CASE 
        WHEN ? = 1 THEN learning_streak + 1
        ELSE 0
      END,
      updated_at = strftime('%s', 'now')
  `;
  
  const correctCount = isCorrect ? 1 : 0;
  const wrongCount = isCorrect ? 0 : 1;
  const streak = isCorrect ? 1 : 0;
  
  db.run(updateQuery, [
    wordId, correctCount, wrongCount, isLearned, streak,
    correctCount, wrongCount, isLearned, streak
  ], function(err) {
    if (err) {
      console.error('Erreur lors de la mise à jour des progrès:', err);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    res.json({ message: 'Progrès mis à jour avec succès' });
  });
});

// GET /api/export - Exporter toutes les données
app.get('/api/export', (req, res) => {
  const format = req.query.format || 'json';
  
  const query = `
    SELECT w.*, lp.view_count, lp.practice_count, lp.is_learned,
           GROUP_CONCAT(DISTINCT f.id) as is_favorite
    FROM words w
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    LEFT JOIN favorites f ON w.id = f.word_id
    GROUP BY w.id
    ORDER BY w.id
  `;
  
  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    const words = rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      viewCount: row.view_count || 0,
      practiceCount: row.practice_count || 0,
      isLearned: Boolean(row.is_learned),
      isFavorite: Boolean(row.is_favorite)
    }));
    
    if (format === 'csv') {
      const headers = [
        'ID', 'Mot Zarma', 'Signification Française', 'Exemple Zarma', 'Exemple Français',
        'Catégorie', 'Difficulté', 'Prononciation', 'Étymologie', 'Synonymes',
        'Antonymes', 'Mots Liés', 'Créé le', 'Modifié le'
      ];
      
      const csvRows = [headers.join(',')];
      words.forEach(word => {
        const row = [
          word.id,
          `"${word.zarmaWord}"`,
          `"${word.frenchMeaning}"`,
          `"${word.zarmaExample}"`,
          `"${word.frenchExample}"`,
          `"${word.category || ''}"`,
          word.difficultyLevel,
          `"${word.pronunciation || ''}"`,
          `"${word.etymology || ''}"`,
          `"${word.synonyms.join(';')}"`,
          `"${word.antonyms.join(';')}"`,
          `"${word.relatedWords.join(';')}"`,
          new Date(word.createdAt * 1000).toISOString(),
          new Date(word.updatedAt * 1000).toISOString()
        ];
        csvRows.push(row.join(','));
      });
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="dictionnaire_zarma.csv"');
      return res.send(csvRows.join('\n'));
    }
    
    // Format JSON par défaut
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="dictionnaire_zarma.json"');
    res.json({
      exportDate: new Date().toISOString(),
      version: '1.0',
      totalWords: words.length,
      data: words
    });
  });
});

// POST /api/import - Importer des données depuis un fichier (protégé)
app.post('/api/import', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Aucun fichier fourni' });
  }
  
  const filePath = req.file.path;
  const fileExtension = path.extname(req.file.originalname).toLowerCase();
  
  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    let wordsToImport = [];
    
    if (fileExtension === '.json') {
      const jsonData = JSON.parse(fileContent);
      wordsToImport = Array.isArray(jsonData) ? jsonData : jsonData.data || [];
    } else if (fileExtension === '.csv') {
      const lines = fileContent.split('\n');
      const headers = lines[0].split(',');
      
      for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        if (values.length >= 5) {
          wordsToImport.push({
            zarmaWord: values[1].replace(/"/g, ''),
            frenchMeaning: values[2].replace(/"/g, ''),
            zarmaExample: values[3].replace(/"/g, ''),
            frenchExample: values[4].replace(/"/g, ''),
            category: values[5] ? values[5].replace(/"/g, '') : null,
            difficultyLevel: parseInt(values[6]) || 1,
            pronunciation: values[7] ? values[7].replace(/"/g, '') : null,
            etymology: values[8] ? values[8].replace(/"/g, '') : null
          });
        }
      }
    }
    
    if (wordsToImport.length === 0) {
      return res.status(400).json({ error: 'Aucun mot valide trouvé dans le fichier' });
    }
    
    // Insérer les mots en base
    let imported = 0;
    let errors = 0;
    
    const insertPromises = wordsToImport.map(word => {
      return new Promise((resolve) => {
        db.run(`
          INSERT INTO words (
            zarma_word, zarma_example, french_meaning, french_example,
            category, difficulty_level, pronunciation, etymology
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          word.zarmaWord, word.zarmaExample, word.frenchMeaning, word.frenchExample,
          word.category, word.difficultyLevel, word.pronunciation, word.etymology
        ], function(err) {
          if (err) {
            console.error('Erreur import:', err);
            errors++;
          } else {
            imported++;
            // Initialiser les progrès
            db.run('INSERT INTO learning_progress (word_id) VALUES (?)', [this.lastID]);
          }
          resolve();
        });
      });
    });
    
    Promise.all(insertPromises).then(() => {
      // Nettoyer le fichier temporaire
      fs.unlinkSync(filePath);
      
      res.json({
        message: `Import terminé: ${imported} mots importés, ${errors} erreurs`,
        imported,
        errors
      });
    });
    
  } catch (error) {
    console.error('Erreur lors de l\'import:', error);
    fs.unlinkSync(filePath);
    res.status(500).json({ error: 'Erreur lors du traitement du fichier' });
  }
});

// POST /api/sync - Point de synchronisation pour l'application mobile
app.post('/api/sync', (req, res) => {
  const { lastSync, deviceId } = req.body;
  
  let query = `
    SELECT w.*, 
           lp.view_count, lp.practice_count, lp.is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
  `;
  
  const params = [];
  
  if (lastSync) {
    query += ` WHERE w.updated_at > ?`;
    params.push(lastSync);
  }
  
  query += ` ORDER BY w.updated_at DESC`;
  
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur de synchronisation' });
    }
    
    const words = rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
    
    res.json({
      words,
      syncTime: Math.floor(Date.now() / 1000),
      total: words.length
    });
  });
});

// Routes d'administration protégées

// GET /api/admin/users - Liste des utilisateurs (super admin seulement)
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  db.all(`
    SELECT id, username, email, role, is_active, last_login, created_at
    FROM admin_users 
    ORDER BY created_at DESC
  `, [], (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    res.json(users);
  });
});

// POST /api/admin/users - Créer un nouvel utilisateur (super admin seulement)
app.post('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const { username, password, email, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 6 caractères' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    
    db.run(
      'INSERT INTO admin_users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
      [username, passwordHash, email, role || 'admin'],
      function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
          }
          console.error('Erreur lors de la création d\'utilisateur:', err);
          return res.status(500).json({ error: 'Erreur lors de la création d\'utilisateur' });
        }
        
        res.status(201).json({
          id: this.lastID,
          message: 'Utilisateur créé avec succès'
        });
      }
    );
  } catch (error) {
    console.error('Erreur lors du hachage du mot de passe:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// PUT /api/admin/users/:id - Modifier un utilisateur (super admin seulement)
app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const userId = req.params.id;
  const { username, email, role, isActive, password } = req.body;

  try {
    let query = `
      UPDATE admin_users SET 
        username = ?, email = ?, role = ?, is_active = ?,
        updated_at = strftime('%s', 'now')
    `;
    let params = [username, email, role, isActive ? 1 : 0];

    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'Le mot de passe doit faire au moins 6 caractères' });
      }
      const passwordHash = await bcrypt.hash(password, 12);
      query += ', password_hash = ?';
      params.push(passwordHash);
    }

    query += ' WHERE id = ?';
    params.push(userId);

    db.run(query, params, function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
          return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
        }
        console.error('Erreur lors de la modification d\'utilisateur:', err);
        return res.status(500).json({ error: 'Erreur lors de la modification d\'utilisateur' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Utilisateur non trouvé' });
      }

      res.json({ message: 'Utilisateur modifié avec succès' });
    });
  } catch (error) {
    console.error('Erreur lors de la modification d\'utilisateur:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// DELETE /api/admin/users/:id - Supprimer un utilisateur (super admin seulement)
app.delete('/api/admin/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const userId = req.params.id;

  // Empêcher la suppression de son propre compte
  if (parseInt(userId) === req.user.userId) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  }

  db.run('DELETE FROM admin_users WHERE id = ?', [userId], function(err) {
    if (err) {
      console.error('Erreur lors de la suppression d\'utilisateur:', err);
      return res.status(500).json({ error: 'Erreur lors de la suppression d\'utilisateur' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ message: 'Utilisateur supprimé avec succès' });
  });
});

// GET /api/admin/sessions - Liste des sessions actives
app.get('/api/admin/sessions', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  db.all(`
    SELECT s.id, s.ip_address, s.user_agent, s.expires_at, s.is_remember_me, s.created_at,
           u.username
    FROM admin_sessions s
    JOIN admin_users u ON s.user_id = u.id
    WHERE s.expires_at > strftime('%s', 'now')
    ORDER BY s.created_at DESC
  `, [], (err, sessions) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    res.json(sessions);
  });
});

// DELETE /api/admin/sessions/:id - Supprimer une session
app.delete('/api/admin/sessions/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const sessionId = req.params.id;
  
  db.run('DELETE FROM admin_sessions WHERE id = ?', [sessionId], function(err) {
    if (err) {
      console.error('Erreur lors de la suppression de session:', err);
      return res.status(500).json({ error: 'Erreur lors de la suppression de session' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Session non trouvée' });
    }

    res.json({ message: 'Session supprimée avec succès' });
  });
});

// GET /api/admin/login-attempts - Historique des tentatives de connexion
app.get('/api/admin/login-attempts', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const limit = req.query.limit || 100;

  db.all(`
    SELECT ip_address, username, success, attempt_time, user_agent
    FROM login_attempts
    ORDER BY attempt_time DESC
    LIMIT ?
  `, [limit], (err, attempts) => {
    if (err) {
      return res.status(500).json({ error: 'Erreur serveur' });
    }
    
    res.json(attempts);
  });
});

// Servir l'interface d'administration
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Gestionnaire d'erreur global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Une erreur interne s\'est produite' });
});

// Middleware 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint non trouvé' });
});

// Nettoyage périodique des sessions expirées
setInterval(() => {
  db.run('DELETE FROM admin_sessions WHERE expires_at < ?', [Math.floor(Date.now() / 1000)], (err) => {
    if (err) {
      console.error('Erreur lors du nettoyage des sessions:', err);
    }
  });
}, 60 * 60 * 1000); // Toutes les heures

// Démarrage du serveur
// Remplacez la section de démarrage du serveur par :

const os = require('os');

// Fonction pour obtenir l'adresse IP locale
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const devName in interfaces) {
    const iface = interfaces[devName];
    for (let i = 0; i < iface.length; i++) {
      const alias = iface[i];
      if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) {
        return alias.address;
      }
    }
  }
  return '127.0.0.1';
}

// Démarrage du serveur sur toutes les interfaces
app.listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  
  console.log(`🚀 Serveur API Dictionnaire Zarma avec authentification démarré sur le port ${PORT}`);
  console.log(`📱 Interface d'administration: http://localhost:${PORT}`);
  console.log(`🌐 Accessible localement sur: http://${localIP}:${PORT}`);
  console.log(`🔗 API disponible sur: http://${localIP}:${PORT}/api`);
  console.log(`📱 Pour mobile/émulateur: http://${localIP}:${PORT}/api`);
  console.log(`🔐 Authentification requise pour les routes d'administration`);
  console.log(`\n📍 Utilisez cette IP dans votre app Flutter: ${localIP}`);
  
  // Créer les dossiers nécessaires
  if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
    console.log('📁 Dossier uploads créé');
  }
  
  if (!fs.existsSync('public')) {
    fs.mkdirSync('public');
    console.log('📁 Dossier public créé');
  }
  
  console.log(`\n🧪 Test de l'API: http://${localIP}:${PORT}/api/test`);
});

// Gestionnaire d'erreur pour le serveur
process.on('EADDRINUSE', (err) => {
  console.error(`❌ Port ${PORT} déjà utilisé. Essayez un autre port ou arrêtez le processus utilisant ce port.`);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('❌ Erreur non gérée:', err);
  process.exit(1);
});
// Route de debug pour voir les données (À SUPPRIMER EN PRODUCTION)
app.get('/api/debug/tables', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const queries = {
    words: 'SELECT * FROM words LIMIT 10',
    admin_users: 'SELECT id, username, email, role, is_active, created_at FROM admin_users',
    admin_sessions: 'SELECT * FROM admin_sessions WHERE expires_at > strftime("%s", "now")',
    favorites: 'SELECT * FROM favorites LIMIT 10',
    learning_progress: 'SELECT * FROM learning_progress LIMIT 10'
  };

  const results = {};
  const promises = Object.keys(queries).map(table => {
    return new Promise((resolve) => {
      db.all(queries[table], [], (err, rows) => {
        results[table] = err ? { error: err.message } : rows;
        resolve();
      });
    });
  });

  Promise.all(promises).then(() => {
    res.json(results);
  });
});
// Gestion propre de l'arrêt du serveur
process.on('SIGINT', () => {
  console.log('\n🛑 Arrêt du serveur...');
  db.close((err) => {
    if (err) {
      console.error('Erreur lors de la fermeture de la base de données:', err);
    } else {
      console.log('✅ Base de données fermée proprement');
    }
    process.exit(0);
  });
});

module.exports = app;