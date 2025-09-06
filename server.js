// server.js - Backend API pour le Dictionnaire Zarma avec Authentification (PostgreSQL)
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
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

// Configuration PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'zarma_dictionary',
  password: process.env.DB_PASSWORD || 'your_password',
  port: process.env.DB_PORT || 5432,
});

// Test de la connexion PostgreSQL
pool.on('connect', () => {
  console.log('✅ Connecté à la base de données PostgreSQL');
});

pool.on('error', (err) => {
  console.error('❌ Erreur de connexion à PostgreSQL:', err);
  process.exit(-1);
});

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

// Configuration CORS
const allowedOrigins = process.env.NODE_ENV === 'production' 
  ? ['https://dictionnaire-zarma.onrender.com', 'https://votre-domaine.com']
  : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
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

// Création des tables PostgreSQL
async function initializeDatabase() {
  try {
    const client = await pool.connect();
    
    // Table des utilisateurs administrateurs
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_users(
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'admin',
        is_active BOOLEAN DEFAULT TRUE,
        last_login BIGINT,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    // Table des sessions
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        expires_at BIGINT NOT NULL,
        is_remember_me BOOLEAN DEFAULT FALSE,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
      )
    `);

    // Table des tentatives de connexion
    await client.query(`
      CREATE TABLE IF NOT EXISTS login_attempts(
        id SERIAL PRIMARY KEY,
        ip_address TEXT NOT NULL,
        username TEXT,
        success BOOLEAN NOT NULL,
        attempt_time BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        user_agent TEXT
      )
    `);

    // Table principale des mots
    await client.query(`
      CREATE TABLE IF NOT EXISTS words(
        id SERIAL PRIMARY KEY,
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
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    // Table des favoris
    await client.query(`
      CREATE TABLE IF NOT EXISTS favorites(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        FOREIGN KEY (word_id) REFERENCES words(id) ON DELETE CASCADE
      )
    `);

    // Table des progrès d'apprentissage
    await client.query(`
      CREATE TABLE IF NOT EXISTS learning_progress(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL,
        view_count INTEGER DEFAULT 0,
        practice_count INTEGER DEFAULT 0,
        correct_answers INTEGER DEFAULT 0,
        wrong_answers INTEGER DEFAULT 0,
        is_learned BOOLEAN DEFAULT FALSE,
        last_practiced BIGINT,
        learning_streak INTEGER DEFAULT 0,
        difficulty_adjustment REAL DEFAULT 1.0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        FOREIGN KEY (word_id) REFERENCES words(id) ON DELETE CASCADE
      )
    `);

    // Table des notes utilisateur
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_notes(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL,
        note_text TEXT NOT NULL,
        tags TEXT,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        FOREIGN KEY (word_id) REFERENCES words(id) ON DELETE CASCADE
      )
    `);

    // Table des statistiques d'utilisation
    await client.query(`
      CREATE TABLE IF NOT EXISTS usage_stats(
        id SERIAL PRIMARY KEY,
        date TEXT NOT NULL,
        words_studied INTEGER DEFAULT 0,
        time_spent INTEGER DEFAULT 0,
        quiz_completed INTEGER DEFAULT 0,
        new_words_learned INTEGER DEFAULT 0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    // Index pour améliorer les performances
    await client.query('CREATE INDEX IF NOT EXISTS idx_words_zarma ON words(zarma_word)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_words_french ON words(french_meaning)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_words_category ON words(category)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token_hash)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)');

    client.release();
    
    // Créer un utilisateur admin par défaut
    await createDefaultAdmin();
    
    console.log('✅ Base de données PostgreSQL initialisée avec succès');
  } catch (error) {
    console.error('❌ Erreur lors de l\'initialisation de la base de données:', error);
  }
}

// Création de l'administrateur par défaut
async function createDefaultAdmin() {
  const defaultUsername = 'admin';
  const defaultPassword = 'admin123'; // CHANGEZ CECI EN PRODUCTION !

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id FROM admin_users WHERE username = $1', [defaultUsername]);
    
    if (result.rows.length === 0) {
      const passwordHash = await bcrypt.hash(defaultPassword, 12);
      
      await client.query(
        'INSERT INTO admin_users (username, password_hash, email, role) VALUES ($1, $2, $3, $4)',
        [defaultUsername, passwordHash, 'admin@dictionnaire-zarma.com', 'super_admin']
      );
      
      console.log('👤 Administrateur par défaut créé:');
      console.log('   Utilisateur: admin');
      console.log('   Mot de passe: admin123');
      console.log('   ⚠️  CHANGEZ CES IDENTIFIANTS EN PRODUCTION !');
    }
    
    client.release();
  } catch (error) {
    console.error('Erreur lors de la création de l\'admin:', error);
  }
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
    try {
      const client = await pool.connect();
      const result = await client.query(
        `SELECT s.*, u.username, u.is_active, u.role 
         FROM admin_sessions s 
         JOIN admin_users u ON s.user_id = u.id 
         WHERE s.user_id = $1 AND s.expires_at > $2 AND u.is_active = TRUE 
         ORDER BY s.created_at DESC LIMIT 1`,
        [decoded.userId, Math.floor(Date.now() / 1000)]
      );
      
      client.release();

      if (result.rows.length === 0) {
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
      req.session = result.rows[0];
      next();
    } catch (dbError) {
      console.error('Erreur lors de la vérification de session:', dbError);
      return res.status(500).json({ 
        error: 'Erreur interne du serveur',
        code: 'SERVER_ERROR'
      });
    }
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
    const client = await pool.connect();
    
    // Recherche de l'utilisateur
    const userResult = await client.query(
      'SELECT * FROM admin_users WHERE username = $1 AND is_active = TRUE',
      [username]
    );

    let loginSuccess = false;
    let user = userResult.rows[0];

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
        await client.query('DELETE FROM admin_sessions WHERE expires_at < $1', [Math.floor(Date.now() / 1000)]);
        
        // Stocker la session dans la base
        await client.query(
          'INSERT INTO admin_sessions (user_id, token_hash, ip_address, user_agent, expires_at, is_remember_me) VALUES ($1, $2, $3, $4, $5, $6)',
          [user.id, token.substring(0, 50), ipAddress, userAgent, expiresAt, rememberMe]
        );

        // Mettre à jour la dernière connexion
        await client.query('UPDATE admin_users SET last_login = EXTRACT(EPOCH FROM NOW()) WHERE id = $1', [user.id]);

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
    await client.query(
      'INSERT INTO login_attempts (ip_address, username, success, user_agent) VALUES ($1, $2, $3, $4)',
      [ipAddress, username, loginSuccess, userAgent]
    );

    client.release();
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur interne du serveur'
    });
  }
});

// Route de déconnexion
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  
  try {
    const client = await pool.connect();
    // Supprimer toutes les sessions de l'utilisateur
    await client.query('DELETE FROM admin_sessions WHERE user_id = $1', [userId]);
    client.release();
    
    res.json({
      success: true,
      message: 'Déconnexion réussie'
    });
  } catch (error) {
    console.error('Erreur lors de la déconnexion:', error);
    return res.status(500).json({
      success: false,
      message: 'Erreur lors de la déconnexion'
    });
  }
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
    const client = await pool.connect();
    
    // Vérifier le mot de passe actuel
    const userResult = await client.query('SELECT password_hash FROM admin_users WHERE id = $1', [userId]);
    
    if (userResult.rows.length === 0) {
      client.release();
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    const user = userResult.rows[0];
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
    
    if (!isCurrentPasswordValid) {
      client.release();
      return res.status(400).json({
        success: false,
        message: 'Mot de passe actuel incorrect'
      });
    }

    // Hacher le nouveau mot de passe
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // Mettre à jour le mot de passe
    await client.query(
      'UPDATE admin_users SET password_hash = $1, updated_at = EXTRACT(EPOCH FROM NOW()) WHERE id = $2',
      [newPasswordHash, userId]
    );

    // Supprimer toutes les autres sessions
    await client.query('DELETE FROM admin_sessions WHERE user_id = $1 AND token_hash != $2', 
      [userId, req.session.token_hash]);

    client.release();

    res.json({
      success: true,
      message: 'Mot de passe changé avec succès'
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
app.get('/api/words', async (req, res) => {
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
  let paramCount = 0;
  
  if (search) {
    paramCount++;
    query += ` AND (w.zarma_word ILIKE $${paramCount} OR w.french_meaning ILIKE $${paramCount} OR w.zarma_example ILIKE $${paramCount} OR w.french_example ILIKE $${paramCount})`;
    const searchParam = `%${search}%`;
    params.push(searchParam);
  }
  
  if (category) {
    paramCount++;
    query += ` AND w.category = $${paramCount}`;
    params.push(category);
  }
  
  if (difficulty) {
    paramCount++;
    query += ` AND w.difficulty_level = $${paramCount}`;
    params.push(difficulty);
  }
  
  query += ` ORDER BY w.usage_frequency DESC, w.zarma_word ASC`;
  
  if (limit) {
    paramCount++;
    query += ` LIMIT $${paramCount}`;
    params.push(parseInt(limit));
    
    if (offset) {
      paramCount++;
      query += ` OFFSET $${paramCount}`;
      params.push(parseInt(offset));
    }
  }
  
  try {
    const client = await pool.connect();
    const result = await client.query(query, params);
    client.release();
    
    // Transformer les données pour le format attendu
    const words = result.rows.map(row => ({
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
  } catch (error) {
    console.error('Erreur lors de la récupération des mots:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/words/:id - Récupérer un mot spécifique
app.get('/api/words/:id', async (req, res) => {
  const id = req.params.id;
  
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT w.*, 
             lp.view_count, lp.practice_count, lp.correct_answers, lp.wrong_answers, 
             lp.is_learned, lp.last_practiced, lp.learning_streak,
             (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) as is_favorite
      FROM words w 
      LEFT JOIN learning_progress lp ON w.id = lp.word_id
      WHERE w.id = $1
    `, [id]);
    
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    const row = result.rows[0];
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
    try {
      const updateClient = await pool.connect();
      await updateClient.query(`
        INSERT INTO learning_progress (word_id, view_count) 
        VALUES ($1, 1) 
        ON CONFLICT(word_id) DO UPDATE SET 
          view_count = learning_progress.view_count + 1,
          updated_at = EXTRACT(EPOCH FROM NOW())
      `, [id]);
      updateClient.release();
    } catch (updateError) {
      console.error('Erreur lors de la mise à jour des vues:', updateError);
    }
    
    res.json(word);
  } catch (error) {
    console.error('Erreur lors de la récupération du mot:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/words - Créer un nouveau mot (protégé)
app.post('/api/words', authenticateToken, validateWord, async (req, res) => {
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
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    RETURNING id
  `;
  
  const params = [
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel || 1, etymology,
    joinCommaSeparated(synonyms),
    joinCommaSeparated(antonyms),
    joinCommaSeparated(relatedWords)
  ];
  
  try {
    const client = await pool.connect();
    const result = await client.query(query, params);
    const wordId = result.rows[0].id;
    
    // Initialiser les progrès d'apprentissage
    await client.query(`INSERT INTO learning_progress (word_id) VALUES ($1)`, [wordId]);
    
    client.release();
    
    res.status(201).json({ 
      id: wordId, 
      message: 'Mot ajouté avec succès'
    });
  } catch (error) {
    console.error('Erreur lors de l\'ajout du mot:', error);
    return res.status(500).json({ error: 'Erreur lors de l\'ajout du mot' });
  }
});

// PUT /api/words/:id - Modifier un mot existant (protégé)
app.put('/api/words/:id', authenticateToken, validateWord, async (req, res) => {
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
      zarma_word = $1, zarma_example = $2, french_meaning = $3, french_example = $4,
      category = $5, pronunciation = $6, difficulty_level = $7, etymology = $8,
      synonyms = $9, antonyms = $10, related_words = $11,
      updated_at = EXTRACT(EPOCH FROM NOW())
    WHERE id = $12
  `;
  
  const params = [
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel || 1, etymology,
    joinCommaSeparated(synonyms),
    joinCommaSeparated(antonyms),
    joinCommaSeparated(relatedWords),
    id
  ];
  
  try {
    const client = await pool.connect();
    const result = await client.query(query, params);
    client.release();
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    res.json({ message: 'Mot modifié avec succès' });
  } catch (error) {
    console.error('Erreur lors de la modification du mot:', error);
    return res.status(500).json({ error: 'Erreur lors de la modification du mot' });
  }
});

// DELETE /api/words/:id - Supprimer un mot (protégé)
app.delete('/api/words/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  
  try {
    const client = await pool.connect();
    const result = await client.query('DELETE FROM words WHERE id = $1', [id]);
    client.release();
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    res.json({ message: 'Mot supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression du mot:', error);
    return res.status(500).json({ error: 'Erreur lors de la suppression du mot' });
  }
});

// GET /api/categories - Récupérer toutes les catégories avec statistiques
app.get('/api/categories', async (req, res) => {
  const query = `
    SELECT 
      category,
      COUNT(*) as word_count,
      AVG(difficulty_level) as avg_difficulty,
      SUM(CASE WHEN lp.is_learned = TRUE THEN 1 ELSE 0 END) as learned_count
    FROM words w
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE category IS NOT NULL
    GROUP BY category
    ORDER BY word_count DESC
  `;
  
  try {
    const client = await pool.connect();
    const result = await client.query(query);
    client.release();
    
    const categories = result.rows.map(row => ({
      name: row.category,
      wordCount: row.word_count,
      avgDifficulty: Math.round(row.avg_difficulty * 10) / 10,
      learnedCount: row.learned_count || 0,
      progressPercentage: row.word_count > 0 ? Math.round((row.learned_count || 0) / row.word_count * 100) : 0
    }));
    
    res.json(categories);
  } catch (error) {
    console.error('Erreur lors de la récupération des catégories:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/stats - Récupérer les statistiques générales
app.get('/api/stats', async (req, res) => {
  const statsQueries = {
    totalWords: 'SELECT COUNT(*) as count FROM words',
    totalCategories: 'SELECT COUNT(DISTINCT category) as count FROM words WHERE category IS NOT NULL',
    avgDifficulty: 'SELECT AVG(difficulty_level) as avg FROM words',
    learnedWords: 'SELECT COUNT(*) as count FROM learning_progress WHERE is_learned = TRUE',
    totalFavorites: 'SELECT COUNT(*) as count FROM favorites',
    wordsThisWeek: `SELECT COUNT(*) as count FROM words WHERE created_at > EXTRACT(EPOCH FROM NOW() - INTERVAL '7 days')`,
    mostViewedWords: `SELECT w.zarma_word, w.french_meaning, lp.view_count FROM words w JOIN learning_progress lp ON w.id = lp.word_id ORDER BY lp.view_count DESC LIMIT 5`,
    categoryDistribution: `SELECT category, COUNT(*) as count FROM words WHERE category IS NOT NULL GROUP BY category ORDER BY count DESC`
  };
  
  const stats = {};
  
  try {
    const client = await pool.connect();
    
    for (const [key, query] of Object.entries(statsQueries)) {
      const result = await client.query(query);
      
      if (key === 'mostViewedWords' || key === 'categoryDistribution') {
        stats[key] = result.rows;
      } else {
        stats[key] = result.rows[0]?.count !== undefined ? result.rows[0].count : result.rows[0]?.avg || 0;
      }
    }
    
    client.release();
    
    // Calculer le taux de complétion
    const completionRate = stats.totalWords > 0 ? 
      Math.round((stats.learnedWords / stats.totalWords) * 100) : 0;
    
    res.json({
      ...stats,
      avgDifficulty: Math.round(stats.avgDifficulty * 10) / 10,
      completionRate
    });
  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/favorites/:wordId - Ajouter/retirer des favoris
app.post('/api/favorites/:wordId', async (req, res) => {
  const wordId = req.params.wordId;
  
  try {
    const client = await pool.connect();
    
    // Vérifier si le mot existe
    const wordResult = await client.query('SELECT id FROM words WHERE id = $1', [wordId]);
    if (wordResult.rows.length === 0) {
      client.release();
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    // Vérifier si déjà en favoris
    const favoriteResult = await client.query('SELECT id FROM favorites WHERE word_id = $1', [wordId]);
    
    if (favoriteResult.rows.length > 0) {
      // Retirer des favoris
      await client.query('DELETE FROM favorites WHERE word_id = $1', [wordId]);
      client.release();
      res.json({ isFavorite: false, message: 'Retiré des favoris' });
    } else {
      // Ajouter aux favoris
      await client.query('INSERT INTO favorites (word_id) VALUES ($1)', [wordId]);
      client.release();
      res.json({ isFavorite: true, message: 'Ajouté aux favoris' });
    }
  } catch (error) {
    console.error('Erreur lors de la gestion des favoris:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/favorites - Récupérer tous les mots favoris
app.get('/api/favorites', async (req, res) => {
  const query = `
    SELECT w.*, f.created_at as favorited_at
    FROM words w
    INNER JOIN favorites f ON w.id = f.word_id
    ORDER BY f.created_at DESC
  `;
  
  try {
    const client = await pool.connect();
    const result = await client.query(query);
    client.release();
    
    const favorites = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      favoritedAt: row.favorited_at
    }));
    
    res.json(favorites);
  } catch (error) {
    console.error('Erreur lors de la récupération des favoris:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/progress/:wordId - Mettre à jour les progrès d'apprentissage
app.post('/api/progress/:wordId', async (req, res) => {
  const wordId = req.params.wordId;
  const { isCorrect, isLearned } = req.body;
  
  const updateQuery = `
    INSERT INTO learning_progress (
      word_id, practice_count, correct_answers, wrong_answers, 
      is_learned, last_practiced, learning_streak, updated_at
    ) VALUES ($1, 1, $2, $3, $4, EXTRACT(EPOCH FROM NOW()), $5, EXTRACT(EPOCH FROM NOW()))
    ON CONFLICT (word_id) DO UPDATE SET
      practice_count = learning_progress.practice_count + 1,
      correct_answers = learning_progress.correct_answers + $6,
      wrong_answers = learning_progress.wrong_answers + $7,
      is_learned = COALESCE($8, learning_progress.is_learned),
      last_practiced = EXTRACT(EPOCH FROM NOW()),
      learning_streak = CASE 
        WHEN $9 = 1 THEN learning_progress.learning_streak + 1
        ELSE 0
      END,
      updated_at = EXTRACT(EPOCH FROM NOW())
  `;
  
  const correctCount = isCorrect ? 1 : 0;
  const wrongCount = isCorrect ? 0 : 1;
  const streak = isCorrect ? 1 : 0;
  
  try {
    const client = await pool.connect();
    await client.query(updateQuery, [
      wordId, correctCount, wrongCount, isLearned, streak,
      correctCount, wrongCount, isLearned, streak
    ]);
    client.release();
    
    res.json({ message: 'Progrès mis à jour avec succès' });
  } catch (error) {
    console.error('Erreur lors de la mise à jour des progrès:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/export - Exporter toutes les données
app.get('/api/export', async (req, res) => {
  const format = req.query.format || 'json';
  
  const query = `
    SELECT w.*, lp.view_count, lp.practice_count, lp.is_learned,
           EXISTS(SELECT 1 FROM favorites f WHERE f.word_id = w.id) as is_favorite
    FROM words w
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    ORDER BY w.id
  `;
  
  try {
    const client = await pool.connect();
    const result = await client.query(query);
    client.release();
    
    const words = result.rows.map(row => ({
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
  } catch (error) {
    console.error('Erreur lors de l\'export:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/import - Importer des données depuis un fichier (protégé)
app.post('/api/import', authenticateToken, upload.single('file'), async (req, res) => {
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
    
    const client = await pool.connect();
    
    for (const word of wordsToImport) {
      try {
        const result = await client.query(`
          INSERT INTO words (
            zarma_word, zarma_example, french_meaning, french_example,
            category, difficulty_level, pronunciation, etymology
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING id
        `, [
          word.zarmaWord, word.zarmaExample, word.frenchMeaning, word.frenchExample,
          word.category, word.difficultyLevel, word.pronunciation, word.etymology
        ]);
        
        imported++;
        // Initialiser les progrès
        await client.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [result.rows[0].id]);
      } catch (err) {
        console.error('Erreur import:', err);
        errors++;
      }
    }
    
    client.release();
    
    // Nettoyer le fichier temporaire
    fs.unlinkSync(filePath);
    
    res.json({
      message: `Import terminé: ${imported} mots importés, ${errors} erreurs`,
      imported,
      errors
    });
  } catch (error) {
    console.error('Erreur lors de l\'import:', error);
    fs.unlinkSync(filePath);
    res.status(500).json({ error: 'Erreur lors du traitement du fichier' });
  }
});

// POST /api/sync - Point de synchronisation pour l'application mobile
app.post('/api/sync', async (req, res) => {
  const { lastSync, deviceId } = req.body;
  
  let query = `
    SELECT w.*, 
           lp.view_count, lp.practice_count, lp.is_learned,
           EXISTS(SELECT 1 FROM favorites f WHERE f.word_id = w.id) as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
  `;
  
  const params = [];
  
  if (lastSync) {
    query += ` WHERE w.updated_at > $1`;
    params.push(lastSync);
  }
  
  query += ` ORDER BY w.updated_at DESC`;
  
  try {
    const client = await pool.connect();
    const result = await client.query(query, params);
    client.release();
    
    const words = result.rows.map(row => ({
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
  } catch (error) {
    console.error('Erreur lors de la synchronisation:', error);
    return res.status(500).json({ error: 'Erreur de synchronisation' });
  }
});

// Routes d'administration protégées

// GET /api/admin/users - Liste des utilisateurs (super admin seulement)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT id, username, email, role, is_active, last_login, created_at
      FROM admin_users 
      ORDER BY created_at DESC
    `);
    client.release();
    
    res.json(result.rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des utilisateurs:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
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
    const client = await pool.connect();
    
    const result = await client.query(
      'INSERT INTO admin_users (username, password_hash, email, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [username, passwordHash, email, role || 'admin']
    );
    
    client.release();
    
    res.status(201).json({
      id: result.rows[0].id,
      message: 'Utilisateur créé avec succès'
    });
  } catch (error) {
    if (error.code === '23505') { // Code d'erreur PostgreSQL pour contrainte unique
      return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
    }
    console.error('Erreur lors de la création d\'utilisateur:', error);
    return res.status(500).json({ error: 'Erreur lors de la création d\'utilisateur' });
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
        username = $1, email = $2, role = $3, is_active = $4,
        updated_at = EXTRACT(EPOCH FROM NOW())
    `;
    let params = [username, email, role, isActive];
    let paramCount = 4;

    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'Le mot de passe doit faire au moins 6 caractères' });
      }
      const passwordHash = await bcrypt.hash(password, 12);
      query += `, password_hash = $${++paramCount}`;
      params.push(passwordHash);
    }

    query += ` WHERE id = $${++paramCount}`;
    params.push(userId);

    const client = await pool.connect();
    const result = await client.query(query, params);
    client.release();

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ message: 'Utilisateur modifié avec succès' });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Ce nom d\'utilisateur existe déjà' });
    }
    console.error('Erreur lors de la modification d\'utilisateur:', error);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
});

// DELETE /api/admin/users/:id - Supprimer un utilisateur (super admin seulement)
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const userId = req.params.id;

  // Empêcher la suppression de son propre compte
  if (parseInt(userId) === req.user.userId) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query('DELETE FROM admin_users WHERE id = $1', [userId]);
    client.release();

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression d\'utilisateur:', error);
    return res.status(500).json({ error: 'Erreur lors de la suppression d\'utilisateur' });
  }
});

// GET /api/admin/sessions - Liste des sessions actives
app.get('/api/admin/sessions', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT s.id, s.ip_address, s.user_agent, s.expires_at, s.is_remember_me, s.created_at,
             u.username
      FROM admin_sessions s
      JOIN admin_users u ON s.user_id = u.id
      WHERE s.expires_at > EXTRACT(EPOCH FROM NOW())
      ORDER BY s.created_at DESC
    `);
    client.release();
    
    res.json(result.rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des sessions:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// DELETE /api/admin/sessions/:id - Supprimer une session
app.delete('/api/admin/sessions/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const sessionId = req.params.id;
  
  try {
    const client = await pool.connect();
    const result = await client.query('DELETE FROM admin_sessions WHERE id = $1', [sessionId]);
    client.release();

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Session non trouvée' });
    }

    res.json({ message: 'Session supprimée avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression de session:', error);
    return res.status(500).json({ error: 'Erreur lors de la suppression de session' });
  }
});

// GET /api/admin/login-attempts - Historique des tentatives de connexion
app.get('/api/admin/login-attempts', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const limit = req.query.limit || 100;

  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT ip_address, username, success, attempt_time, user_agent
      FROM login_attempts
      ORDER BY attempt_time DESC
      LIMIT $1
    `, [limit]);
    client.release();
    
    res.json(result.rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des tentatives de connexion:', error);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
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
setInterval(async () => {
  try {
    const client = await pool.connect();
    await client.query('DELETE FROM admin_sessions WHERE expires_at < $1', [Math.floor(Date.now() / 1000)]);
    client.release();
  } catch (error) {
    console.error('Erreur lors du nettoyage des sessions:', error);
  }
}, 60 * 60 * 1000); // Toutes les heures

// Démarrage du serveur
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

// Initialiser la base de données et démarrer le serveur
initializeDatabase().then(() => {
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
app.get('/api/debug/tables', authenticateToken, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  const queries = {
    words: 'SELECT * FROM words LIMIT 10',
    admin_users: 'SELECT id, username, email, role, is_active, created_at FROM admin_users',
    admin_sessions: 'SELECT * FROM admin_sessions WHERE expires_at > EXTRACT(EPOCH FROM NOW())',
    favorites: 'SELECT * FROM favorites LIMIT 10',
    learning_progress: 'SELECT * FROM learning_progress LIMIT 10'
  };

  const results = {};
  
  try {
    const client = await pool.connect();
    
    for (const [table, query] of Object.entries(queries)) {
      try {
        const result = await client.query(query);
        results[table] = result.rows;
      } catch (error) {
        results[table] = { error: error.message };
      }
    }
    
    client.release();
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des données' });
  }
});

// Gestion propre de l'arrêt du serveur
process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur...');
  try {
    await pool.end();
    console.log('✅ Connexion à la base de données fermée proprement');
  } catch (error) {
    console.error('Erreur lors de la fermeture de la base de données:', error);
  }
  process.exit(0);
});

module.exports = app;
