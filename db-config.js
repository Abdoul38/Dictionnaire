// db-config.js - Configuration PostgreSQL améliorée
const { Pool } = require('pg');

// Configuration PostgreSQL avec gestion des déconnexions
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  // Configuration de pool améliorée
  max: parseInt(process.env.DB_POOL_MAX) || 10,
  min: 2, // Maintenir au minimum 2 connexions
  idleTimeoutMillis: parseInt(process.env.DB_POOL_IDLE_TIMEOUT_MS) || 30000,
  connectionTimeoutMillis: 20000, // Timeout de connexion
  acquireTimeoutMillis: 30000, // Timeout d'acquisition
  createTimeoutMillis: 20000,
  destroyTimeoutMillis: 5000,
  reapIntervalMillis: 1000,
  createRetryIntervalMillis: 200,
  // Reconnexion automatique
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
  // Configuration SSL plus robuste pour la production
  ...(process.env.NODE_ENV === 'production' && {
    ssl: {
      rejectUnauthorized: false,
      sslmode: 'require'
    }
  })
});

// Gestion des événements de pool
pool.on('connect', (client) => {
  console.log(`✅ Nouvelle connexion PostgreSQL établie (PID: ${client.processID})`);
});

pool.on('acquire', (client) => {
  console.log(`🔄 Connexion PostgreSQL acquise (PID: ${client.processID})`);
});

pool.on('error', (err, client) => {
  console.error('❌ Erreur PostgreSQL pool:', err);
  console.error('Client info:', client ? `PID: ${client.processID}` : 'Client non disponible');
  
  // Tentative de reconnexion après erreur
  setTimeout(() => {
    console.log('🔄 Tentative de reconnexion PostgreSQL...');
    testConnection();
  }, 5000);
});

pool.on('remove', (client) => {
  console.log(`🗑️ Connexion PostgreSQL supprimée (PID: ${client.processID})`);
});

// Fonction de test de connexion
async function testConnection() {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW() as current_time, version() as version');
    console.log('✅ Test connexion PostgreSQL réussi:', result.rows[0].current_time);
    client.release();
    return true;
  } catch (error) {
    console.error('❌ Test connexion PostgreSQL échoué:', error.message);
    return false;
  }
}

// Fonction de santé de la base de données
async function healthCheck() {
  try {
    const start = Date.now();
    const client = await pool.connect();
    const result = await client.query('SELECT 1 as health_check');
    const duration = Date.now() - start;
    client.release();
    
    return {
      healthy: true,
      responseTime: duration,
      totalConnections: pool.totalCount,
      idleConnections: pool.idleCount,
      waitingCount: pool.waitingCount
    };
  } catch (error) {
    console.error('❌ Health check PostgreSQL échoué:', error);
    return {
      healthy: false,
      error: error.message,
      totalConnections: pool.totalCount,
      idleConnections: pool.idleCount,
      waitingCount: pool.waitingCount
    };
  }
}

// Middleware de gestion des erreurs de base de données
function handleDatabaseError(error, req, res, next) {
  console.error('❌ Erreur base de données:', error);
  
  if (error.code === 'ECONNRESET' || 
      error.code === 'ENOTFOUND' || 
      error.code === 'ECONNREFUSED' ||
      error.message.includes('connection terminated')) {
    
    console.log('🔄 Tentative de reconnexion automatique...');
    
    return res.status(503).json({
      error: 'Service temporairement indisponible',
      message: 'Problème de connexion à la base de données. Veuillez réessayer.',
      code: 'DB_CONNECTION_ERROR',
      retry: true
    });
  }
  
  // Autres erreurs de base de données
  return res.status(500).json({
    error: 'Erreur de base de données',
    message: 'Une erreur est survenue lors de l\'accès aux données',
    code: 'DB_ERROR'
  });
}

// Fonction wrapper pour les requêtes avec retry automatique
async function queryWithRetry(text, params = [], maxRetries = 3) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const client = await pool.connect();
      try {
        const result = await client.query(text, params);
        return result;
      } finally {
        client.release();
      }
    } catch (error) {
      lastError = error;
      console.error(`❌ Tentative ${attempt}/${maxRetries} échouée:`, error.message);
      
      if (attempt === maxRetries) {
        throw lastError;
      }
      
      // Délai exponentiel entre les tentatives
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
      console.log(`⏳ Attente ${delay}ms avant la prochaine tentative...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

module.exports = {
  pool,
  testConnection,
  healthCheck,
  handleDatabaseError,
  queryWithRetry
};

