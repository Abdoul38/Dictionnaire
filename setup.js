#!/usr/bin/env node

// setup.js - Script d'initialisation du Dictionnaire Zarma
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('🚀 Configuration initiale du Dictionnaire Zarma\n');

async function question(prompt) {
  return new Promise(resolve => {
    rl.question(prompt, resolve);
  });
}

async function setup() {
  try {
    // 1. Créer les dossiers nécessaires
    console.log('📁 Création des dossiers...');
    const folders = ['uploads', 'public', 'logs', 'backups'];
    
    folders.forEach(folder => {
      if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true });
        console.log(`   ✅ Dossier ${folder} créé`);
      } else {
        console.log(`   ℹ️  Dossier ${folder} existe déjà`);
      }
    });

    // 2. Générer une clé JWT sécurisée
    console.log('\n🔐 Génération de la clé JWT...');
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    console.log('   ✅ Clé JWT générée');

    // 3. Configuration de l'environnement
    console.log('\n⚙️  Configuration de l\'environnement...');
    
    const port = await question('Port du serveur (3000): ') || '3000';
    const nodeEnv = await question('Environnement (development/production) [development]: ') || 'development';
    const allowedOrigins = await question('Domaines CORS autorisés [http://localhost:3000]: ') || 'http://localhost:3000';

    // 4. Configuration de l'administrateur
    console.log('\n👤 Configuration de l\'administrateur...');
    const adminUsername = await question('Nom d\'utilisateur admin [admin]: ') || 'admin';
    const adminEmail = await question('Email admin [admin@dictionnaire-zarma.com]: ') || 'admin@dictionnaire-zarma.com';
    
    let adminPassword;
    while (!adminPassword || adminPassword.length < 6) {
      adminPassword = await question('Mot de passe admin (min 6 caractères): ');
      if (!adminPassword || adminPassword.length < 6) {
        console.log('   ❌ Le mot de passe doit faire au moins 6 caractères');
      }
    }

    // 5. Créer le fichier .env
    console.log('\n📝 Création du fichier .env...');
    const envContent = `# Configuration du serveur
PORT=${port}
NODE_ENV=${nodeEnv}

# Sécurité JWT
JWT_SECRET=${jwtSecret}

# CORS
ALLOWED_ORIGINS=${allowedOrigins}

# Base de données
DB_PATH=./dictionary.db

# Upload de fichiers
MAX_FILE_SIZE=10485760
UPLOAD_PATH=./uploads

# Rate limiting
LOGIN_RATE_LIMIT_MAX=5
LOGIN_RATE_LIMIT_WINDOW_MS=900000
API_RATE_LIMIT_MAX=100
API_RATE_LIMIT_WINDOW_MS=900000

# Sessions
ADMIN_SESSION_DURATION=8h
REMEMBER_SESSION_DURATION=30d

# Sécurité
BCRYPT_ROUNDS=12

# Logs
LOG_LEVEL=info
LOG_FILE=./logs/app.log

# Backup automatique
BACKUP_ENABLED=true
BACKUP_INTERVAL_HOURS=24
BACKUP_RETENTION_DAYS=30
BACKUP_PATH=./backups

# Administrateur par défaut
DEFAULT_ADMIN_USERNAME=${adminUsername}
DEFAULT_ADMIN_EMAIL=${adminEmail}
DEFAULT_ADMIN_PASSWORD=${adminPassword}
`;

    fs.writeFileSync('.env', envContent);
    console.log('   ✅ Fichier .env créé');

    // 6. Créer une page d'index simple
    console.log('\n🌐 Création de la page d\'accueil...');
    const indexHtml = `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dictionnaire Zarma - Administration</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
        }
        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        .logo h1 {
            color: #333;
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }
        .logo p {
            color: #666;
            font-size: 0.9rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            margin-top: 1rem;
        }
        .btn:hover {
            background: #5a6fd8;
        }
        .status {
            text-align: center;
            margin-top: 1rem;
            padding: 0.5rem;
            border-radius: 5px;
            display: none;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-top: 1rem;
        }
        .checkbox-group input[type="checkbox"] {
            width: auto;
            margin-right: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>📚 Dictionnaire Zarma</h1>
            <p>Interface d'Administration</p>
        </div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Nom d'utilisateur</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="rememberMe" name="rememberMe">
                <label for="rememberMe">Se souvenir de moi</label>
            </div>
            
            <button type="submit" class="btn">Se connecter</button>
            
            <div id="status" class="status"></div>
        </form>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const status = document.getElementById('status');
            const formData = new FormData(e.target);
            
            const loginData = {
                username: formData.get('username'),
                password: formData.get('password'),
                rememberMe: formData.get('rememberMe') === 'on'
            };
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(loginData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    localStorage.setItem('authToken', result.token);
                    status.textContent = 'Connexion réussie ! Redirection...';
                    status.className = 'status success';
                    status.style.display = 'block';
                    
                    setTimeout(() => {
                        // Rediriger vers le dashboard ou une autre page
                        window.location.href = '/dashboard.html';
                    }, 1000);
                } else {
                    status.textContent = result.message || 'Erreur de connexion';
                    status.className = 'status error';
                    status.style.display = 'block';
                }
            } catch (error) {
                status.textContent = 'Erreur de connexion au serveur';
                status.className = 'status error';
                status.style.display = 'block';
            }
        });
    </script>
</body>
</html>`;

    fs.writeFileSync('public/index.html', indexHtml);
    console.log('   ✅ Page d\'accueil créée');

    // 7. Créer un fichier README
    console.log('\n📖 Création du fichier README...');
    const readmeContent = `# Dictionnaire Zarma API

API backend sécurisée pour le Dictionnaire Zarma avec authentification complète.

## 🚀 Démarrage rapide

### Installation des dépendances
\`\`\`bash
npm install
\`\`\`

### Configuration
Le fichier \`.env\` a été créé automatiquement avec vos paramètres.

### Démarrage du serveur
\`\`\`bash
# Mode développement
npm run dev

# Mode production
npm start
\`\`\`

## 📱 Accès

- **Interface d'administration**: http://localhost:${port}
- **API**: http://localhost:${port}/api

### Identifiants par défaut
- **Utilisateur**: ${adminUsername}
- **Mot de passe**: ${adminPassword}

⚠️ **Important**: Changez ces identifiants après la première connexion !

## 🔗 Endpoints principaux

### Authentification
- \`POST /api/auth/login\` - Connexion
- \`POST /api/auth/logout\` - Déconnexion
- \`GET /api/auth/verify\` - Vérification du token
- \`POST /api/auth/change-password\` - Changement de mot de passe

### Mots du dictionnaire
- \`GET /api/words\` - Liste des mots (public)
- \`GET /api/words/:id\` - Détails d'un mot (public)
- \`POST /api/words\` - Créer un mot (protégé)
- \`PUT /api/words/:id\` - Modifier un mot (protégé)
- \`DELETE /api/words/:id\` - Supprimer un mot (protégé)

### Gestion des utilisateurs (super admin)
- \`GET /api/admin/users\` - Liste des utilisateurs
- \`POST /api/admin/users\` - Créer un utilisateur
- \`PUT /api/admin/users/:id\` - Modifier un utilisateur
- \`DELETE /api/admin/users/:id\` - Supprimer un utilisateur

### Statistiques et monitoring
- \`GET /api/stats\` - Statistiques générales
- \`GET /api/categories\` - Liste des catégories
- \`GET /api/admin/sessions\` - Sessions actives
- \`GET /api/admin/login-attempts\` - Tentatives de connexion

## 🛡️ Sécurité

- Authentification JWT avec rotation des tokens
- Hachage des mots de passe avec bcrypt
- Rate limiting sur les connexions
- Protection CORS
- Headers de sécurité avec Helmet
- Sessions avec expiration
- Logs des tentatives de connexion

## 📊 Base de données

La base de données SQLite est automatiquement créée avec les tables suivantes :
- \`admin_users\` - Utilisateurs administrateurs
- \`admin_sessions\` - Sessions actives
- \`words\` - Mots du dictionnaire
- \`favorites\` - Mots favoris
- \`learning_progress\` - Progrès d'apprentissage

## 🔄 Sauvegarde

Les sauvegardes automatiques sont configurées dans le fichier \`.env\`.

## 📝 Logs

Les logs sont sauvegardés dans le dossier \`logs/\`.

## 🤝 Contribution

1. Fork le projet
2. Créez votre branche (\`git checkout -b feature/AmazingFeature\`)
3. Commitez vos changements (\`git commit -m 'Add some AmazingFeature'\`)
4. Push vers la branche (\`git push origin feature/AmazingFeature\`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.
`;

    fs.writeFileSync('README.md', readmeContent);
    console.log('   ✅ Fichier README créé');

    // 8. Finalisation
    console.log('\n✨ Configuration terminée !');
    console.log('\n📋 Prochaines étapes :');
    console.log('   1. Installez les dépendances : npm install');
    console.log('   2. Démarrez le serveur : npm start ou npm run dev');
    console.log(`   3. Accédez à http://localhost:${port}`);
    console.log(`   4. Connectez-vous avec : ${adminUsername} / ${adminPassword}`);
    console.log('\n🔐 N\'oubliez pas de changer le mot de passe par défaut !');

  } catch (error) {
    console.error('❌ Erreur lors de la configuration :', error.message);
  } finally {
    rl.close();
  }
}

// Vérifier si le setup a déjà été fait
if (fs.existsSync('.env')) {
  console.log('⚠️  Le fichier .env existe déjà.');
  question('Voulez-vous refaire la configuration ? (y/N): ').then(answer => {
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      setup();
    } else {
      console.log('Configuration annulée.');
      rl.close();
    }
  });
} else {
  setup();
}