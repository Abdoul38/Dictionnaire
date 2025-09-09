// server.js - Version corrigée pour Render.com avec PostgreSQL
require('dotenv').config();
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

// Configuration de la base de données PostgreSQL pour Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false
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

// Configuration CORS
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

// Middleware de logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} from ${req.ip}`);
  next();
});

// Middleware de parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Créer le dossier uploads s'il n'existe pas
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configuration Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.json', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Type de fichier non supporté. Utilisez .json ou .csv'), false);
    }
  }
});

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limite à 5 tentatives
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

// Appliquer le rate limiting aux API
app.use('/api', apiLimiter);

// Routes de base
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

// GET /api/auth/verify - Vérifier un token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token valide',
    user: req.user
  });
});

// POST /api/auth/logout - Déconnexion
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM admin_sessions WHERE token_hash LIKE $1', [
      req.headers['authorization']?.split(' ')[1]?.substring(0, 50) || ''
    ]);
    
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error('Erreur lors de la déconnexion:', error);
    res.status(500).json({ success: false, message: 'Erreur lors de la déconnexion' });
  }
});

// Routes pour les mots
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

// GET /api/words/:id - Récupérer un mot spécifique
app.get('/api/words/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT w.*, 
             COALESCE(lp.view_count, 0) as view_count, 
             COALESCE(lp.practice_count, 0) as practice_count, 
             COALESCE(lp.is_learned, false) as is_learned
      FROM words w 
      LEFT JOIN learning_progress lp ON w.id = lp.word_id
      WHERE w.id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    const word = result.rows[0];
    res.json({
      id: word.id,
      zarmaWord: word.zarma_word,
      zarmaExample: word.zarma_example,
      frenchMeaning: word.french_meaning,
      frenchExample: word.french_example,
      category: word.category,
      pronunciation: word.pronunciation,
      difficultyLevel: word.difficulty_level,
      etymology: word.etymology,
      synonyms: parseCommaSeparated(word.synonyms),
      antonyms: parseCommaSeparated(word.antonyms),
      relatedWords: parseCommaSeparated(word.related_words),
      usageFrequency: word.usage_frequency,
      audioPath: word.audio_path,
      imagePath: word.image_path,
      createdAt: word.created_at,
      updatedAt: word.updated_at,
      viewCount: word.view_count,
      practiceCount: word.practice_count,
      isLearned: word.is_learned
    });
  } catch (error) {
    console.error('Erreur lors de la récupération du mot:', error);
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

// PUT /api/words/:id - Modifier un mot (protégé)
app.put('/api/words/:id', authenticateToken, validateWord, async (req, res) => {
  const { id } = req.params;
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
    await pool.query(`
      UPDATE words SET
        zarma_word = $1,
        zarma_example = $2,
        french_meaning = $3,
        french_example = $4,
        category = $5,
        pronunciation = $6,
        difficulty_level = $7,
        etymology = $8,
        synonyms = $9,
        antonyms = $10,
        related_words = $11,
        updated_at = EXTRACT(EPOCH FROM NOW())
      WHERE id = $12
    `, [
      zarmaWord, zarmaExample, frenchMeaning, frenchExample,
      category, pronunciation, difficultyLevel || 1, etymology,
      joinCommaSeparated(synonyms),
      joinCommaSeparated(antonyms),
      joinCommaSeparated(relatedWords),
      id
    ]);
    
    res.json({ message: 'Mot modifié avec succès' });
  } catch (error) {
    console.error('Erreur lors de la modification du mot:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du mot' });
  }
});

// DELETE /api/words/:id - Supprimer un mot (protégé)
app.delete('/api/words/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    await pool.query('DELETE FROM words WHERE id = $1', [id]);
    res.json({ message: 'Mot supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression du mot:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du mot' });
  }
});

// GET /api/stats - Statistiques du dictionnaire
app.get('/api/stats', async (req, res) => {
  try {
    // Statistiques de base
    const totalWordsResult = await pool.query('SELECT COUNT(*) as count FROM words');
    const totalWords = parseInt(totalWordsResult.rows[0].count);

    const categoriesResult = await pool.query('SELECT COUNT(DISTINCT category) as count FROM words WHERE category IS NOT NULL AND category != \'\'');
    const totalCategories = parseInt(categoriesResult.rows[0].count);

    const avgDifficultyResult = await pool.query('SELECT AVG(difficulty_level) as avg FROM words');
    const avgDifficulty = parseFloat(avgDifficultyResult.rows[0].avg || 0).toFixed(1);

    // Calcul du taux de complétion (mots avec tous les champs remplis)
    const completeWordsResult = await pool.query(`
      SELECT COUNT(*) as count FROM words 
      WHERE pronunciation IS NOT NULL AND pronunciation != ''
        AND etymology IS NOT NULL AND etymology != ''
        AND synonyms IS NOT NULL AND synonyms != ''
    `);
    const completeWords = parseInt(completeWordsResult.rows[0].count);
    const completionRate = totalWords > 0 ? Math.round((completeWords / totalWords) * 100) : 0;

    // Répartition par catégories
    const categoryDistributionResult = await pool.query(`
      SELECT category, COUNT(*) as count 
      FROM words 
      WHERE category IS NOT NULL AND category != ''
      GROUP BY category 
      ORDER BY count DESC
    `);

    const categoryDistribution = categoryDistributionResult.rows.map(row => ({
      category: row.category,
      count: parseInt(row.count)
    }));

    res.json({
      totalWords,
      totalCategories,
      avgDifficulty,
      completionRate,
      categoryDistribution
    });
  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
  }
});

// GET /api/export - Export des données
// Corrections pour les fonctions d'export et d'import dans server.js

// GET /api/export - Export des données (CORRIGÉ)
app.get('/api/export', async (req, res) => {
  const { format } = req.query;
  
  try {
    const result = await pool.query(`
      SELECT 
        zarma_word, french_meaning, zarma_example, french_example,
        category, pronunciation, difficulty_level, etymology,
        synonyms, antonyms, related_words, created_at, updated_at
      FROM words 
      ORDER BY zarma_word
    `);

    const words = result.rows.map(row => ({
      zarmaWord: row.zarma_word,
      frenchMeaning: row.french_meaning,
      zarmaExample: row.zarma_example,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: row.synonyms,
      antonyms: row.antonyms,
      relatedWords: row.related_words,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));

    if (format === 'csv') {
      // Export CSV avec encodage UTF-8
      let csv = '\uFEFF'; // BOM UTF-8
      csv += 'Mot Zarma,Signification Française,Exemple Zarma,Exemple Français,Catégorie,Prononciation,Niveau,Étymologie,Synonymes,Antonymes,Mots Liés\n';
      
      words.forEach(word => {
        const escapeCsvField = (field) => {
          if (!field) return '';
          const str = String(field).replace(/"/g, '""');
          // Entourer de guillemets si contient virgule, guillemet ou saut de ligne
          if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str}"`;
          }
          return str;
        };
        
        const row = [
          escapeCsvField(word.zarmaWord),
          escapeCsvField(word.frenchMeaning),
          escapeCsvField(word.zarmaExample),
          escapeCsvField(word.frenchExample),
          escapeCsvField(word.category),
          escapeCsvField(word.pronunciation),
          word.difficultyLevel || 1,
          escapeCsvField(word.etymology),
          escapeCsvField(word.synonyms),
          escapeCsvField(word.antonyms),
          escapeCsvField(word.relatedWords)
        ].join(',');
        
        csv += row + '\n';
      });

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="dictionnaire_zarma.csv"');
      res.send(csv);
    } else {
      // Export JSON (par défaut)
      const exportData = {
        exportDate: new Date().toISOString(),
        totalWords: words.length,
        version: '1.0',
        words: words
      };
      
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="dictionnaire_zarma.json"');
      res.json(exportData);
    }
  } catch (error) {
    console.error('Erreur lors de l\'export:', error);
    res.status(500).json({ error: 'Erreur lors de l\'export des données: ' + error.message });
  }
});

// POST /api/import - Import des données (CORRIGÉ)
// POST /api/import - Import des données (MODIFIÉ pour accepter les doublons)
app.post('/api/import', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Aucun fichier fourni' });
  }

  const filePath = req.file.path;
  const fileExtension = path.extname(req.file.originalname).toLowerCase();

  try {
    let wordsToImport = [];

    if (fileExtension === '.json') {
      // Import JSON
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(fileContent);
      
      if (data.words && Array.isArray(data.words)) {
        wordsToImport = data.words;
      } else if (Array.isArray(data)) {
        wordsToImport = data;
      } else {
        throw new Error('Format JSON invalide. Le fichier doit contenir un tableau de mots.');
      }
    } else if (fileExtension === '.csv') {
      // Import CSV amélioré
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const lines = fileContent.replace(/^\uFEFF/, '').split('\n'); // Retirer BOM UTF-8
      
      if (lines.length < 2) {
        throw new Error('Le fichier CSV doit contenir au moins une ligne d\'en-tête et une ligne de données');
      }
      
      // Parser CSV manuel pour gérer les champs entre guillemets
      const parseCsvLine = (line) => {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
          const char = line[i];
          
          if (char === '"') {
            if (inQuotes && line[i + 1] === '"') {
              // Double quote = quote échappée
              current += '"';
              i++; // Skip next quote
            } else {
              // Toggle quote mode
              inQuotes = !inQuotes;
            }
          } else if (char === ',' && !inQuotes) {
            // End of field
            result.push(current.trim());
            current = '';
          } else {
            current += char;
          }
        }
        
        // Add last field
        result.push(current.trim());
        return result;
      };
      
      const headers = parseCsvLine(lines[0]);
      console.log('En-têtes CSV détectés:', headers);
      
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line) {
          const values = parseCsvLine(line);
          
          if (values.length >= 4 && values[0] && values[1] && values[2] && values[3]) {
            const word = {
              zarmaWord: values[0] || '',
              frenchMeaning: values[1] || '',
              zarmaExample: values[2] || '',
              frenchExample: values[3] || '',
              category: values[4] || null,
              pronunciation: values[5] || null,
              difficultyLevel: parseInt(values[6]) || 1,
              etymology: values[7] || null,
              synonyms: values[8] ? values[8].split(';').map(s => s.trim()).filter(s => s) : [],
              antonyms: values[9] ? values[9].split(';').map(s => s.trim()).filter(s => s) : [],
              relatedWords: values[10] ? values[10].split(';').map(s => s.trim()).filter(s => s) : []
            };
            
            wordsToImport.push(word);
          }
        }
      }
    } else {
      throw new Error('Format de fichier non supporté. Utilisez .json ou .csv');
    }

    console.log(`Tentative d'import de ${wordsToImport.length} mots (avec doublons autorisés)`);

    let importedCount = 0;
    let errorCount = 0;
    const errors = [];

    // Import des mots avec transaction - TOUJOURS CRÉER DE NOUVEAUX ENREGISTREMENTS
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      for (let i = 0; i < wordsToImport.length; i++) {
        const word = wordsToImport[i];
        
        try {
          // Validation des champs requis
          if (!word.zarmaWord || !word.frenchMeaning || !word.zarmaExample || !word.frenchExample) {
            errors.push(`Ligne ${i + 1}: Champs requis manquants (zarmaWord, frenchMeaning, zarmaExample, frenchExample)`);
            errorCount++;
            continue;
          }

          // TOUJOURS créer un nouveau mot (pas de vérification d'existence)
          const result = await client.query(`
            INSERT INTO words (
              zarma_word, zarma_example, french_meaning, french_example,
              category, pronunciation, difficulty_level, etymology,
              synonyms, antonyms, related_words
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
          `, [
            word.zarmaWord,
            word.zarmaExample,
            word.frenchMeaning,
            word.frenchExample,
            word.category,
            word.pronunciation,
            word.difficultyLevel || 1,
            word.etymology,
            joinCommaSeparated(word.synonyms),
            joinCommaSeparated(word.antonyms),
            joinCommaSeparated(word.relatedWords)
          ]);
          
          // Initialiser les progrès d'apprentissage pour le nouveau mot
          await client.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [result.rows[0].id]);
          
          importedCount++;
          
        } catch (wordError) {
          console.error(`Erreur lors de l'import du mot "${word.zarmaWord}":`, wordError);
          errors.push(`Mot "${word.zarmaWord}" (ligne ${i + 1}): ${wordError.message}`);
          errorCount++;
        }
      }
      
      await client.query('COMMIT');
      console.log(`Import terminé: ${importedCount} mots créés, ${errorCount} erreurs`);
      
    } catch (transactionError) {
      await client.query('ROLLBACK');
      throw transactionError;
    } finally {
      client.release();
    }

    // Nettoyer le fichier temporaire
    try {
      fs.unlinkSync(filePath);
    } catch (cleanupError) {
      console.error('Erreur lors du nettoyage du fichier:', cleanupError);
    }

    res.json({
      success: true,
      message: `Import terminé: ${importedCount} mots créés (doublons autorisés), ${errorCount} erreurs`,
      imported: importedCount,
      updated: 0, // Plus de mise à jour, seulement des créations
      errors: errorCount,
      errorDetails: errors.length > 0 ? errors.slice(0, 10) : [], // Limiter à 10 erreurs pour la réponse
      duplicatesAllowed: true
    });
    
  } catch (error) {
    console.error('Erreur lors de l\'import:', error);
    
    // Nettoyer le fichier temporaire en cas d'erreur
    try {
      fs.unlinkSync(filePath);
    } catch (cleanupError) {
      console.error('Erreur lors du nettoyage du fichier:', cleanupError);
    }
    
    res.status(500).json({ 
      error: 'Erreur lors de l\'import: ' + error.message,
      success: false
    });
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

// Routes pour les favoris
app.post('/api/favorites/:wordId', async (req, res) => {
  const { wordId } = req.params;
  
  try {
    // Vérifier si le mot existe
    const wordExists = await pool.query('SELECT id FROM words WHERE id = $1', [wordId]);
    if (wordExists.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }

    // Vérifier si déjà en favoris
    const existingFavorite = await pool.query('SELECT id FROM favorites WHERE word_id = $1', [wordId]);
    
    if (existingFavorite.rows.length === 0) {
      await pool.query('INSERT INTO favorites (word_id) VALUES ($1)', [wordId]);
      res.json({ success: true, message: 'Mot ajouté aux favoris' });
    } else {
      res.json({ success: true, message: 'Mot déjà en favoris' });
    }
  } catch (error) {
    console.error('Erreur lors de l\'ajout aux favoris:', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout aux favoris' });
  }
});

app.delete('/api/favorites/:wordId', async (req, res) => {
  const { wordId } = req.params;
  
  try {
    await pool.query('DELETE FROM favorites WHERE word_id = $1', [wordId]);
    res.json({ success: true, message: 'Mot retiré des favoris' });
  } catch (error) {
    console.error('Erreur lors de la suppression des favoris:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression des favoris' });
  }
});

app.get('/api/favorites', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT w.*, f.created_at as favorited_at
      FROM words w
      INNER JOIN favorites f ON w.id = f.word_id
      ORDER BY f.created_at DESC
    `);
    
    const favorites = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      favoritedAt: row.favorited_at
    }));
    
    res.json({ favorites });
  } catch (error) {
    console.error('Erreur lors de la récupération des favoris:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des favoris' });
  }
});

// Routes pour les progrès d'apprentissage
app.post('/api/learning-progress/:wordId', async (req, res) => {
  const { wordId } = req.params;
  const { action, isCorrect } = req.body; // action: 'view', 'practice'
  
  try {
    // Vérifier si le mot existe
    const wordExists = await pool.query('SELECT id FROM words WHERE id = $1', [wordId]);
    if (wordExists.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }

    // Vérifier si un progrès existe déjà
    const existingProgress = await pool.query('SELECT * FROM learning_progress WHERE word_id = $1', [wordId]);
    
    if (existingProgress.rows.length === 0) {
      // Créer un nouvel enregistrement de progrès
      await pool.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [wordId]);
    }

    // Mettre à jour selon l'action
    if (action === 'view') {
      await pool.query(`
        UPDATE learning_progress 
        SET view_count = view_count + 1, updated_at = EXTRACT(EPOCH FROM NOW())
        WHERE word_id = $1
      `, [wordId]);
    } else if (action === 'practice') {
      let updateQuery = `
        UPDATE learning_progress 
        SET practice_count = practice_count + 1, 
            last_practiced = EXTRACT(EPOCH FROM NOW()),
            updated_at = EXTRACT(EPOCH FROM NOW())
      `;
      
      if (isCorrect !== undefined) {
        if (isCorrect) {
          updateQuery += `, correct_answers = correct_answers + 1`;
        } else {
          updateQuery += `, wrong_answers = wrong_answers + 1`;
        }
      }
      
      updateQuery += ` WHERE word_id = $1`;
      await pool.query(updateQuery, [wordId]);
    }

    res.json({ success: true, message: 'Progrès mis à jour' });
  } catch (error) {
    console.error('Erreur lors de la mise à jour des progrès:', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour des progrès' });
  }
});

// Routes pour les catégories
app.get('/api/categories', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT category, COUNT(*) as word_count
      FROM words 
      WHERE category IS NOT NULL AND category != ''
      GROUP BY category
      ORDER BY word_count DESC, category ASC
    `);
    
    const categories = result.rows.map(row => ({
      name: row.category,
      wordCount: parseInt(row.count)
    }));
    
    res.json({ categories });
  } catch (error) {
    console.error('Erreur lors de la récupération des catégories:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des catégories' });
  }
});

// Route pour la recherche avancée
app.post('/api/search', async (req, res) => {
  const { 
    query, 
    searchIn, // ['zarma', 'french', 'examples']
    categories, 
    difficulty, 
    limit = 50, 
    offset = 0 
  } = req.body;
  
  if (!query || query.trim().length < 2) {
    return res.status(400).json({ error: 'La requête de recherche doit contenir au moins 2 caractères' });
  }

  try {
    let sqlQuery = `
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
    
    // Construire la condition de recherche
    const searchConditions = [];
    const searchTerm = `%${query.trim()}%`;
    
    if (!searchIn || searchIn.includes('zarma')) {
      paramCount++;
      searchConditions.push(`w.zarma_word ILIKE ${paramCount}`);
      params.push(searchTerm);
    }
    
    if (!searchIn || searchIn.includes('french')) {
      paramCount++;
      searchConditions.push(`w.french_meaning ILIKE ${paramCount}`);
      params.push(searchTerm);
    }
    
    if (!searchIn || searchIn.includes('examples')) {
      paramCount++;
      searchConditions.push(`w.zarma_example ILIKE ${paramCount}`);
      params.push(searchTerm);
      
      paramCount++;
      searchConditions.push(`w.french_example ILIKE ${paramCount}`);
      params.push(searchTerm);
    }
    
    if (searchConditions.length > 0) {
      sqlQuery += ` AND (${searchConditions.join(' OR ')})`;
    }
    
    // Filtres additionnels
    if (categories && categories.length > 0) {
      paramCount++;
      sqlQuery += ` AND w.category = ANY(${paramCount})`;
      params.push(categories);
    }
    
    if (difficulty && difficulty.length > 0) {
      paramCount++;
      sqlQuery += ` AND w.difficulty_level = ANY(${paramCount})`;
      params.push(difficulty);
    }
    
    sqlQuery += ` ORDER BY w.usage_frequency DESC, w.zarma_word ASC`;
    
    // Pagination
    paramCount++;
    sqlQuery += ` LIMIT ${paramCount}`;
    params.push(parseInt(limit));
    
    paramCount++;
    sqlQuery += ` OFFSET ${paramCount}`;
    params.push(parseInt(offset));
    
    const result = await pool.query(sqlQuery, params);
    
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
    
    res.json({ 
      words, 
      total: words.length,
      hasMore: words.length === parseInt(limit)
    });
  } catch (error) {
    console.error('Erreur lors de la recherche:', error);
    res.status(500).json({ error: 'Erreur lors de la recherche' });
  }
});

// Fonction pour nettoyer les anciennes sessions expirées
async function cleanupExpiredSessions() {
  try {
    const result = await pool.query('DELETE FROM admin_sessions WHERE expires_at < $1', [Math.floor(Date.now() / 1000)]);
    if (result.rowCount > 0) {
      console.log(`Nettoyage: ${result.rowCount} sessions expirées supprimées`);
    }
  } catch (error) {
    console.error('Erreur lors du nettoyage des sessions:', error);
  }
}

// Initialisation de la base de données PostgreSQL
async function initializeDatabase() {
  try {
    // Test de connexion à la base de données
    await pool.query('SELECT NOW()');
    console.log('✅ Connexion à PostgreSQL établie avec succès');

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
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        UNIQUE(word_id)
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
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        UNIQUE(date)
      )
    `);

    // Créer les index
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_zarma ON words(zarma_word)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_french ON words(french_meaning)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_category ON words(category)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_difficulty ON words(difficulty_level)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token_hash)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_learning_progress_word ON learning_progress(word_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_favorites_word ON favorites(word_id)');

    console.log('✅ Base de données PostgreSQL initialisée avec succès');
    
    // Créer un utilisateur admin par défaut
    await createDefaultAdmin();

  } catch (error) {
    console.error('❌ Erreur lors de l\'initialisation de la base de données:', error);
    // Ne pas quitter le processus en production pour permettre les redémarrages
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
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

// Gestion des erreurs non capturées
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Graceful shutdown
  process.exit(1);
});

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

process.on('SIGTERM', async () => {
  console.log('🛑 Signal SIGTERM reçu, arrêt propre...');
  try {
    await pool.end();
    console.log('✅ Connexions PostgreSQL fermées proprement');
  } catch (error) {
    console.error('Erreur lors de la fermeture des connexions:', error);
  }
  process.exit(0);
});

// Nettoyer les sessions expirées toutes les heures
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// Démarrage du serveur
async function startServer() {
  try {
    // Initialiser la base de données
    await initializeDatabase();
    
    // Démarrer le serveur
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur API Dictionnaire Zarma (PostgreSQL) démarré sur le port ${PORT}`);
      console.log(`🔗 API disponible sur: http://localhost:${PORT}/api`);
      console.log(`🔐 Authentification requise pour les routes d'administration`);
      console.log(`💾 Base de données: PostgreSQL`);
      console.log(`🌍 Environnement: ${process.env.NODE_ENV || 'development'}`);
    });

    // Gestion de l'arrêt propre du serveur
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} reçu, arrêt propre du serveur...`);
      server.close(async () => {
        console.log('📴 Serveur HTTP fermé');
        try {
          await pool.end();
          console.log('✅ Connexions PostgreSQL fermées proprement');
        } catch (error) {
          console.error('Erreur lors de la fermeture des connexions:', error);
        }
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error);
    // Ne pas quitter le processus en production
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
}

// Démarrer le serveur
startServer();

module.exports = app;
