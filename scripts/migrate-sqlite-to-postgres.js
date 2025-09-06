// scripts/migrate-sqlite-to-postgres.js
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const path = require('path');

// Configuration PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://zarma_user:zarma_password_2024@localhost:5432/dictionnaire_zarma',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Chemin vers la base SQLite existante
const sqliteDbPath = path.join(__dirname, '..', 'dictionary.db');

async function migrateSQLiteToPostgreSQL() {
  console.log('🔄 Début de la migration SQLite vers PostgreSQL...');
  
  // Ouvrir la base SQLite
  const sqliteDb = new sqlite3.Database(sqliteDbPath, (err) => {
    if (err) {
      console.error('❌ Erreur lors de l\'ouverture de SQLite:', err.message);
      return;
    }
    console.log('✅ Connexion à SQLite réussie');
  });

  try {
    // 1. Migrer les utilisateurs admin
    console.log('📤 Migration des utilisateurs admin...');
    const adminUsers = await getSQLiteData(sqliteDb, 'SELECT * FROM admin_users');
    
    for (const user of adminUsers) {
      await pool.query(`
        INSERT INTO admin_users (username, password_hash, email, role, is_active, last_login, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (username) DO NOTHING
      `, [
        user.username, user.password_hash, user.email, user.role, 
        user.is_active, user.last_login, user.created_at, user.updated_at
      ]);
    }
    console.log(`✅ ${adminUsers.length} utilisateurs admin migrés`);

    // 2. Migrer les mots
    console.log('📤 Migration des mots...');
    const words = await getSQLiteData(sqliteDb, 'SELECT * FROM words');
    
    for (const word of words) {
      const result = await pool.query(`
        INSERT INTO words (
          zarma_word, zarma_example, french_meaning, french_example,
          category, pronunciation, difficulty_level, etymology,
          synonyms, antonyms, related_words, usage_frequency,
          audio_path, image_path, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        RETURNING id
      `, [
        word.zarma_word, word.zarma_example, word.french_meaning, word.french_example,
        word.category, word.pronunciation, word.difficulty_level, word.etymology,
        word.synonyms, word.antonyms, word.related_words, word.usage_frequency,
        word.audio_path, word.image_path, word.created_at, word.updated_at
      ]);
      
      // Mapper l'ancien ID vers le nouveau pour les relations
      const newId = result.rows[0].id;
      wordIdMapping.set(word.id, newId);
    }
    console.log(`✅ ${words.length} mots migrés`);

    // 3. Migrer les favoris
    console.log('📤 Migration des favoris...');
    const favorites = await getSQLiteData(sqliteDb, 'SELECT * FROM favorites');
    
    for (const favorite of favorites) {
      const newWordId = wordIdMapping.get(favorite.word_id);
      if (newWordId) {
        await pool.query(`
          INSERT INTO favorites (word_id, created_at)
          VALUES ($1, $2)
        `, [newWordId, favorite.created_at]);
      }
    }
    console.log(`✅ ${favorites.length} favoris migrés`);

    // 4. Migrer les progrès d'apprentissage
    console.log('📤 Migration des progrès d\'apprentissage...');
    const progressData = await getSQLiteData(sqliteDb, 'SELECT * FROM learning_progress');
    
    for (const progress of progressData) {
      const newWordId = wordIdMapping.get(progress.word_id);
      if (newWordId) {
        await pool.query(`
          INSERT INTO learning_progress (
            word_id, view_count, practice_count, correct_answers, wrong_answers,
            is_learned, last_practiced, learning_streak, difficulty_adjustment,
            created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
          ON CONFLICT (word_id) DO UPDATE SET
            view_count = $2,
            practice_count = $3,
            correct_answers = $4,
            wrong_answers = $5,
            is_learned = $6,
            last_practiced = $7,
            learning_streak = $8,
            difficulty_adjustment = $9,
            updated_at = $11
        `, [
          newWordId, progress.view_count, progress.practice_count,
          progress.correct_answers, progress.wrong_answers, progress.is_learned,
          progress.last_practiced, progress.learning_streak, progress.difficulty_adjustment,
          progress.created_at, progress.updated_at
        ]);
      }
    }
    console.log(`✅ ${progressData.length} progrès migrés`);

    // 5. Migrer les notes utilisateur
    console.log('📤 Migration des notes utilisateur...');
    const userNotes = await getSQLiteData(sqliteDb, 'SELECT * FROM user_notes');
    
    for (const note of userNotes) {
      const newWordId = wordIdMapping.get(note.word_id);
      if (newWordId) {
        await pool.query(`
          INSERT INTO user_notes (word_id, note_text, tags, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5)
        `, [newWordId, note.note_text, note.tags, note.created_at, note.updated_at]);
      }
    }
    console.log(`✅ ${userNotes.length} notes utilisateur migrées`);

    // 6. Migrer les statistiques d'usage
    console.log('📤 Migration des statistiques d\'usage...');
    const usageStats = await getSQLiteData(sqliteDb, 'SELECT * FROM usage_stats');
    
    for (const stat of usageStats) {
      await pool.query(`
        INSERT INTO usage_stats (
          date, words_studied, time_spent, quiz_completed, new_words_learned, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
      `, [stat.date, stat.words_studied, stat.time_spent, stat.quiz_completed, stat.new_words_learned, stat.created_at]);
    }
    console.log(`✅ ${usageStats.length} statistiques migrées`);

    console.log('🎉 Migration complète avec succès !');
    
    // Afficher les statistiques de migration
    const totalWordsResult = await pool.query('SELECT COUNT(*) as count FROM words');
    const totalUsersResult = await pool.query('SELECT COUNT(*) as count FROM admin_users');
    const totalFavoritesResult = await pool.query('SELECT COUNT(*) as count FROM favorites');
    
    console.log('\n📊 Statistiques de migration:');
    console.log(`   - Mots: ${totalWordsResult.rows[0].count}`);
    console.log(`   - Utilisateurs admin: ${totalUsersResult.rows[0].count}`);
    console.log(`   - Favoris: ${totalFavoritesResult.rows[0].count}`);
    console.log('   - Base de données PostgreSQL prête à l\'emploi !');

  } catch (error) {
    console.error('❌ Erreur lors de la migration:', error);
  } finally {
    // Fermer les connexions
    sqliteDb.close();
    await pool.end();
  }
}

// Map pour associer les anciens IDs SQLite aux nouveaux IDs PostgreSQL
const wordIdMapping = new Map();

// Fonction helper pour récupérer des données de SQLite
function getSQLiteData(db, query) {
  return new Promise((resolve, reject) => {
    db.all(query, [], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows || []);
      }
    });
  });
}

// Fonction pour vérifier la connexion PostgreSQL
async function checkPostgreSQLConnection() {
  try {
    const result = await pool.query('SELECT NOW()');
    console.log('✅ Connexion PostgreSQL réussie:', result.rows[0].now);
    return true;
  } catch (error) {
    console.error('❌ Erreur de connexion PostgreSQL:', error.message);
    return false;
  }
}

// Fonction principale
async function main() {
  console.log('🚀 Script de migration SQLite vers PostgreSQL');
  console.log('==========================================\n');

  // Vérifier la connexion PostgreSQL
  const pgConnected = await checkPostgreSQLConnection();
  if (!pgConnected) {
    console.log('💡 Assurez-vous que PostgreSQL est démarré et accessible');
    console.log('   - Docker: docker-compose up -d postgres');
    console.log('   - Local: vérifiez que PostgreSQL est en cours d\'exécution');
    process.exit(1);
  }

  // Vérifier l'existence du fichier SQLite
  const fs = require('fs');
  if (!fs.existsSync(sqliteDbPath)) {
    console.error(`❌ Fichier SQLite non trouvé: ${sqliteDbPath}`);
    console.log('💡 Assurez-vous que votre base SQLite existe avant la migration');
    process.exit(1);
  }

  // Demander confirmation
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  rl.question('⚠️  Cette opération va importer toutes vos données SQLite vers PostgreSQL. Continuer? (y/N): ', (answer) => {
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      migrateSQLiteToPostgreSQL();
    } else {
      console.log('❌ Migration annulée');
    }
    rl.close();
  });
}

// Lancer le script si appelé directement
if (require.main === module) {
  main();
}

module.exports = { migrateSQLiteToPostgreSQL };