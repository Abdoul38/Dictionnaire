const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, '..', 'dictionary.db'));

console.log('=== STRUCTURE DE LA BASE DE DONNÉES ===\n');

// Lister toutes les tables
db.all("SELECT name FROM sqlite_master WHERE type='table'", [], (err, tables) => {
  if (err) {
    console.error(err);
    return;
  }

  console.log('Tables disponibles:');
  tables.forEach(table => {
    console.log(`- ${table.name}`);
  });

  console.log('\n=== DONNÉES DES PRINCIPALES TABLES ===\n');

  // Voir les mots
  db.all("SELECT * FROM words LIMIT 5", [], (err, words) => {
    if (err) {
      console.error(err);
    } else {
      console.log('--- MOTS (5 premiers) ---');
      console.table(words);
    }

    // Voir les utilisateurs admin
    db.all("SELECT id, username, email, role, is_active FROM admin_users", [], (err, users) => {
      if (err) {
        console.error(err);
      } else {
        console.log('--- UTILISATEURS ADMIN ---');
        console.table(users);
      }

      // Statistiques générales
      db.get("SELECT COUNT(*) as total_words FROM words", [], (err, stat1) => {
        db.get("SELECT COUNT(*) as total_users FROM admin_users", [], (err, stat2) => {
          db.get("SELECT COUNT(*) as total_favorites FROM favorites", [], (err, stat3) => {
            console.log('--- STATISTIQUES ---');
            console.log(`Mots total: ${stat1?.total_words || 0}`);
            console.log(`Utilisateurs: ${stat2?.total_users || 0}`);
            console.log(`Favoris: ${stat3?.total_favorites || 0}`);
            
            db.close();
          });
        });
      });
    });
  });
});