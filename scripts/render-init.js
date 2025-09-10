// scripts/render-init.js - Initialisation spécifique pour Render
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 Initialisation pour Render...');

// Créer les dossiers nécessaires dans /data
const dataDirs = ['/data/uploads', '/data/logs', '/data/backups'];
dataDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`✅ Dossier créé: ${dir}`);
  }
});

// Vérifier la connexion à la base de données
console.log('🔍 Vérification de la connexion à la base de données...');
try {
  // Cette commande suppose que vous avez psql installé dans l'environnement Render
  // Render fournit automatiquement la variable DATABASE_URL
  const dbUrl = process.env.DATABASE_URL;
  if (dbUrl) {
    console.log('✅ DATABASE_URL est configurée');
    console.log(`📊 Base de données: ${dbUrl.split('@')[1]?.split('/')[1]}`);
  } else {
    console.log('⚠️ DATABASE_URL non trouvée');
  }
} catch (error) {
  console.log('❌ Erreur lors de la vérification de la base de données:', error.message);
}

console.log('✅ Initialisation Render terminée');