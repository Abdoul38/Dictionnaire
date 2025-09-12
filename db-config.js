const { Pool } = require('pg');

// Configuration du pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // obligatoire avec Neon
  max: 10, // max connexions simultanées
  idleTimeoutMillis: 30000, // 30s avant fermeture d'une connexion inactive
  connectionTimeoutMillis: 5000, // 5s pour tenter de se connecter
});

// Test initial de connexion
async function testConnection() {
  try {
    const result = await pool.query('SELECT NOW()');
    console.log('✅ Connexion PostgreSQL réussie :', result.rows[0].now);
    return true;
  } catch (err) {
    console.error('❌ Erreur de connexion PostgreSQL :', err.message);
    return false;
  }
}

// Vérification de santé de la DB
async function healthCheck() {
  try {
    const result = await pool.query('SELECT NOW()');
    return {
      healthy: true,
      time: result.rows[0].now,
      totalConnections: pool.totalCount,
      idleConnections: pool.idleCount,
      waitingCount: pool.waitingCount,
    };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

// Middleware de gestion des erreurs DB
function handleDatabaseError(err, req, res, next) {
  if (err && err.code) {
    console.error('💥 Erreur DB détectée :', err.message);
    return res.status(500).json({ error: 'Database Error', detail: err.message });
  }
  next(err);
}

// Fonction de requête avec retry automatique
async function queryWithRetry(query, params, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await pool.query(query, params);
    } catch (err) {
      console.error(`⚠️ Tentative ${i + 1} échouée :`, err.message);
      if (i === retries - 1) throw err; // si dernières tentatives -> throw
      await new Promise((resolve) => setTimeout(resolve, 1000 * (i + 1)));
    }
  }
}

module.exports = {
  pool,
  testConnection,
  healthCheck,
  handleDatabaseError,
  queryWithRetry,
};
