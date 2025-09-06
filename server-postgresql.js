// server-postgresql.js - Version avec PostgreSQL pour base centralisée
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

// Configuration de la base de données PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://username:password@localhost:5432/dictionnaire_zarma',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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

app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://172.18.2.199:3000', 
    'http://192.168.1.1:3000',
    'http://192.168.0.1:3000',
    'capacitor://localhost',
    'http://localhost',  
    'https://votre-app-render.onrender.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} from ${req.ip}`);
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Route de test
app.get('/api/test', (req, res) => {
  console.log('Route de test appelée depuis:', req.ip);
  res.json({
    success: true,
    message: 'API fonctionne avec PostgreSQL!',
    timestamp: new Date().toISOString(),
    database: 'PostgreSQL',
    client_ip: req.ip
  });
});

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

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    error: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.',
    lockoutTime: 15
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Trop de requêtes. Réessayez plus tard.'
  }
});

app.use('/api', apiLimiter);

// Initialisation de la base de données PostgreSQL
async function initializeDatabase() {
  try {
    // Créer les tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users(
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email VARCHAR(255),
        role VARCHAR(50) DEFAULT 'admin',
        is_active BOOLEAN DEFAULT TRUE,
        last_login BIGINT,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        ip_address INET,
        user_agent TEXT,
        expires_at BIGINT NOT NULL,
        is_remember_me BOOLEAN DEFAULT FALSE,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_attempts(
        id SERIAL PRIMARY KEY,
        ip_address INET NOT NULL,
        username VARCHAR(255),
        success BOOLEAN NOT NULL,
        attempt_time BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        user_agent TEXT
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS words(
        id SERIAL PRIMARY KEY,
        zarma_word VARCHAR(255) NOT NULL,
        zarma_example TEXT NOT NULL,
        french_meaning TEXT NOT NULL,
        french_example TEXT NOT NULL,
        category VARCHAR(100),
        pronunciation VARCHAR(255),
        difficulty_level INTEGER DEFAULT 1,
        etymology TEXT,
        synonyms TEXT,
        antonyms TEXT,
        related_words TEXT,
        usage_frequency INTEGER DEFAULT 0,
        audio_path VARCHAR(255),
        image_path VARCHAR(255),
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL REFERENCES words(id) ON DELETE CASCADE,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_progress(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL REFERENCES words(id) ON DELETE CASCADE,
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
        UNIQUE(word_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_notes(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL REFERENCES words(id) ON DELETE CASCADE,
        note_text TEXT NOT NULL,
        tags TEXT,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS usage_stats(
        id SERIAL PRIMARY KEY,
        date DATE NOT NULL,
        words_studied INTEGER DEFAULT 0,
        time_spent INTEGER DEFAULT 0,
        quiz_completed INTEGER DEFAULT 0,
        new_words_learned INTEGER DEFAULT 0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    // Créer les index
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_zarma ON words(zarma_word)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_french ON words(french_meaning)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_category ON words(category)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token_hash)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)');

    console.log('✅ Base de données PostgreSQL initialisée avec succès');
    
    // Créer un utilisateur admin par défaut
    await createDefaultAdmin();

  } catch (error) {
    console.error('❌ Erreur lors de l\'initialisation de la base de données:', error);
    process.exit(1);
  }
}

// Création de l'administrateur par défaut
async function createDefaultAdmin() {
  const defaultUsername = 'admin';
  const defaultPassword = 'admin123';

  try {
    const userCheck = await pool.query('SELECT id FROM admin_users WHERE username = $1', [defaultUsername]);
    
    if (userCheck.rows.length === 0) {
      const passwordHash = await bcrypt.hash(defaultPassword, 12);
      
      await pool.query(
        'INSERT INTO admin_users (username, password_hash, email, role) VALUES ($1, $2, $3, $4)',
        [defaultUsername, passwordHash, 'admin@dictionnaire-zarma.com', 'super_admin']
      );
      
      console.log('👤 Administrateur par défaut créé:');
      console.log('   Utilisateur: admin');
      console.log('   Mot de passe: admin123');
      console.log('   ⚠️  CHANGEZ CES IDENTIFIANTS EN PRODUCTION !');
    }
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
    const sessionQuery = `
      SELECT s.*, u.username, u.is_active, u.role 
      FROM admin_sessions s 
      JOIN admin_users u ON s.user_id = u.id 
      WHERE s.user_id = $1 AND s.expires_at > $2 AND u.is_active = TRUE 
      ORDER BY s.created_at DESC LIMIT 1
    `;
    
    const sessionResult = await pool.query(sessionQuery, [decoded.userId, Math.floor(Date.now() / 1000)]);

    if (sessionResult.rows.length === 0) {
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
    req.session = sessionResult.rows[0];
    next();
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
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password, rememberMe } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Nom d\'utilisateur et mot de passe requis'
    });
  }

  try {
    // Recherche de l'utilisateur
    const userResult = await pool.query(
      'SELECT * FROM admin_users WHERE username = $1 AND is_active = TRUE',
      [username]
    );

    let loginSuccess = false;
    const user = userResult.rows[0];

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
        await pool.query('DELETE FROM admin_sessions WHERE expires_at < $1', [Math.floor(Date.now() / 1000)]);
        
        // Stocker la session dans la base
        await pool.query(
          'INSERT INTO admin_sessions (user_id, token_hash, ip_address, user_agent, expires_at, is_remember_me) VALUES ($1, $2, $3, $4, $5, $6)',
          [user.id, token.substring(0, 50), ipAddress, userAgent, expiresAt, rememberMe]
        );

        // Mettre à jour la dernière connexion
        await pool.query('UPDATE admin_users SET last_login = $1 WHERE id = $2', [Math.floor(Date.now() / 1000), user.id]);

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
    await pool.query(
      'INSERT INTO login_attempts (ip_address, username, success, user_agent) VALUES ($1, $2, $3, $4)',
      [ipAddress, username, loginSuccess, userAgent]
    );
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur interne du serveur'
    });
  }
});

// GET /api/words - Récupérer tous les mots avec filtres optionnels
app.get('/api/words', async (req, res) => {
  const { search, category, difficulty, limit, offset } = req.query;
  
  let query = `
    SELECT w.*, 
           COALESCE(lp.view_count, 0) as view_count, 
           COALESCE(lp.practice_count, 0) as practice_count, 
           COALESCE(lp.is_learned, false) as is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) > 0 as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE 1=1
  `;
  
  const params = [];
  let paramCount = 0;
  
  if (search) {
    paramCount++;
    query += ` AND (w.zarma_word ILIKE $${paramCount} OR w.french_meaning ILIKE $${paramCount} OR w.zarma_example ILIKE $${paramCount} OR w.french_example ILIKE $${paramCount})`;
    params.push(`%${search}%`);
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
    const result = await pool.query(query, params);
    
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
      viewCount: row.view_count,
      practiceCount: row.practice_count,
      isLearned: row.is_learned,
      isFavorite: row.is_favorite
    }));
    
    res.json({ words, total: words.length });
  } catch (error) {
    console.error('Erreur lors de la récupération des mots:', error);
    res.status(500).json({ error: 'Erreur serveur' });
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
  
  try {
    const result = await pool.query(`
      INSERT INTO words (
        zarma_word, zarma_example, french_meaning, french_example,
        category, pronunciation, difficulty_level, etymology,
        synonyms, antonyms, related_words
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id
    `, [
      zarmaWord, zarmaExample, frenchMeaning, frenchExample,
      category, pronunciation, difficultyLevel || 1, etymology,
      joinCommaSeparated(synonyms),
      joinCommaSeparated(antonyms),
      joinCommaSeparated(relatedWords)
    ]);
    
    const wordId = result.rows[0].id;
    
    // Initialiser les progrès d'apprentissage
    await pool.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [wordId]);
    
    res.status(201).json({ 
      id: wordId, 
      message: 'Mot ajouté avec succès'
    });
  } catch (error) {
    console.error('Erreur lors de l\'ajout du mot:', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout du mot' });
  }
});

// POST /api/sync - Point de synchronisation pour l'application mobile
app.post('/api/sync', async (req, res) => {
  const { lastSync, deviceId } = req.body;
  
  let query = `
    SELECT w.*, 
           COALESCE(lp.view_count, 0) as view_count, 
           COALESCE(lp.practice_count, 0) as practice_count, 
           COALESCE(lp.is_learned, false) as is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) > 0 as is_favorite
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
    const result = await pool.query(query, params);
    
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
    console.error('Erreur de synchronisation:', error);
    res.status(500).json({ error: 'Erreur de synchronisation' });
  }
});

// Démarrage du serveur
const os = require('os');

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

async function startServer() {
  try {
    // Initialiser la base de données
    await initializeDatabase();
    
    // Démarrer le serveur
    app.listen(PORT, '0.0.0.0', () => {
      const localIP = getLocalIP();
      
      console.log(`🚀 Serveur API Dictionnaire Zarma (PostgreSQL) démarré sur le port ${PORT}`);
      console.log(`📱 Interface d'administration: http://localhost:${PORT}`);
      console.log(`🌍 Accessible localement sur: http://${localIP}:${PORT}`);
      console.log(`🔗 API disponible sur: http://${localIP}:${PORT}/api`);
      console.log(`📱 Pour mobile/émulateur: http://${localIP}:${PORT}/api`);
      console.log(`🔐 Authentification requise pour les routes d'administration`);
      console.log(`\n📍 Utilisez cette IP dans votre app Flutter: ${localIP}`);
      console.log(`🧪 Test de l'API: http://${localIP}:${PORT}/api/test`);
      console.log(`💾 Base de données: PostgreSQL (centralisée)`);
      
      // Créer les dossiers nécessaires
      if (!fs.existsSync('uploads')) {
        fs.mkdirSync('uploads');
        console.log('📁 Dossier uploads créé');
      }
      
      if (!fs.existsSync('public')) {
        fs.mkdirSync('public');
        console.log('📁 Dossier public créé');
      }
    });
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error);
    process.exit(1);
  }
}

// Gestion propre de l'arrêt du serveur
process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur...');
  try {
    await pool.end();
    console.log('✅ Connexions PostgreSQL fermées proprement');
  } catch (error) {
    console.error('Erreur lors de la fermeture des connexions:', error);
  }
  process.exit(0);
});

// Démarrer le serveur
startServer();

module.exports = app;