# Guide de Déploiement - Dictionnaire Zarma

Ce guide vous explique comment déployer votre système complet avec l'interface web d'administration et l'API de synchronisation.

## 📋 Prérequis

### Serveur
- Node.js 16+ 
- NPM ou Yarn
- Serveur web (Apache/Nginx) ou hébergement cloud
- Base de données SQLite (incluse)

### Application Flutter
- Flutter SDK 3.0+
- Packages additionnels à ajouter dans `pubspec.yaml`

## 🚀 Installation du Backend

### 1. Préparation du serveur

```bash
# Créer le dossier du projet
mkdir dictionnaire-zarma-api
cd dictionnaire-zarma-api

# Initialiser le projet Node.js
npm init -y
```

### 2. Installation des dépendances

```bash
# Installer toutes les dépendances
npm install express cors sqlite3 multer express-validator helmet compression

# Dépendances de développement
npm install --save-dev nodemon jest
```

### 3. Structure des fichiers

Créez cette structure de dossiers :

```
dictionnaire-zarma-api/
├── server.js              # Fichier principal du serveur
├── package.json           # Configuration des dépendances
├── public/                # Interface web d'administration
│   └── index.html        # Page d'administration
├── uploads/              # Fichiers uploadés (créé automatiquement)
├── dictionary.db         # Base de données SQLite (créé automatiquement)
└── README.md             # Documentation
```

### 4. Configuration des fichiers

Copiez le code du serveur dans `server.js` et l'interface web dans `public/index.html`.

### 5. Démarrage local pour tests

```bash
# Mode développement avec redémarrage automatique
npm run dev

# Ou mode production
npm start
```

L'interface sera accessible sur `http://localhost:3000`

## 🌐 Déploiement en Production

### Option 1 : VPS/Serveur dédié

#### Configuration Nginx

```nginx
server {
    listen 80;
    server_name votre-domaine.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### Service systemd

Créer `/etc/systemd/system/dictionnaire-zarma.service` :

```ini
[Unit]
Description=Dictionnaire Zarma API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/dictionnaire-zarma-api
ExecStart=/usr/bin/node server.js
Restart=on-failure
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
# Activer et démarrer le service
sudo systemctl enable dictionnaire-zarma
sudo systemctl start dictionnaire-zarma
```

### Option 2 : Heroku

#### Préparation

```bash
# Installer Heroku CLI
npm install -g heroku

# Créer Procfile
echo "web: node server.js" > Procfile

# Initialiser git
git init
git add .
git commit -m "Initial commit"
```

#### Déploiement

```bash
# Créer l'application Heroku
heroku create votre-app-dictionnaire-zarma

# Variables d'environnement
heroku config:set NODE_ENV=production

# Déployer
git push heroku main
```

### Option 3 : Vercel

```json
// vercel.json
{
  "version": 2,
  "builds": [
    {
      "src": "server.js",
      "use": "@vercel/node"
    },
    {
      "src": "public/**",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/server.js"
    },
    {
      "src": "/(.*)",
      "dest": "/public/$1"
    }
  ]
}
```

```bash
# Installer Vercel CLI
npm install -g vercel

# Déployer
vercel --prod
```

## 📱 Configuration de l'Application Flutter

### 1. Ajout des dépendances

Ajoutez dans `pubspec.yaml` :

```yaml
dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0
  connectivity_plus: ^5.0.1
  shared_preferences: ^2.2.2
  sqflite: ^2.3.0
  path: ^1.8.3
  
dev_dependencies:
  flutter_test:
    sdk: flutter
```

### 2. Permissions réseau

#### Android (`android/app/src/main/AndroidManifest.xml`)

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

#### iOS (`ios/Runner/Info.plist`)

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

### 3. Configuration de l'URL API

Dans votre application Flutter, modifiez `ApiService` :

```dart
// lib/services/api_service.dart
class ApiService {
  static const String PRODUCTION_URL = 'https://votre-domaine.com/api';
  static const String STAGING_URL = 'https://votre-app-staging.herokuapp.com/api';
  
  // Le reste du code...
}
```

### 4. Modification du DatabaseHelper

Remplacez votre `DatabaseHelper` existant par `EnhancedDatabaseHelper` pour bénéficier de la synchronisation.

### 5. Ajout d'un écran de synchronisation

Créez un écran de paramètres avec options de synchronisation :

```dart
// lib/screens/sync_settings_screen.dart
class SyncSettingsScreen extends StatefulWidget {
  @override
  _SyncSettingsScreenState createState() => _SyncSettingsScreenState();
}

class _SyncSettingsScreenState extends State<SyncSettingsScreen> {
  final EnhancedDatabaseHelper _db = EnhancedDatabaseHelper();
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Synchronisation')),
      body: Column(
        children: [
          ListTile(
            title: Text('Synchroniser maintenant'),
            subtitle: Text('Synchroniser avec le serveur'),
            trailing: IconButton(
              icon: Icon(Icons.sync),
              onPressed: _performSync,
            ),
          ),
          ListTile(
            title: Text('Configuration serveur'),
            subtitle: Text('Configurer l\'URL du serveur'),
            onTap: _configureServer,
          ),
          FutureBuilder<SyncStatus>(
            future: _db.getSyncStatus(),
            builder: (context, snapshot) {
              if (!snapshot.hasData) return CircularProgressIndicator();
              
              final status = snapshot.data!;
              return ListTile(
                title: Text('Statut'),
                subtitle: Text(status.statusMessage),
                leading: Icon(
                  status.needsSync ? Icons.sync_problem : Icons.sync,
                  color: status.needsSync ? Colors.orange : Colors.green,
                ),
              );
            },
          ),
        ],
      ),
    );
  }
  
  void _performSync() async {
    try {
      await _db.performFullSync();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Synchronisation réussie')),
      );
      setState(() {});
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Erreur de synchronisation: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }
  
  void _configureServer() {
    // Implémenter la configuration de l'URL du serveur
  }
}
```

## 🔧 Configuration et Personnalisation

### Variables d'environnement

Créez un fichier `.env` (ne pas commiter) :

```env
NODE_ENV=production
PORT=3000
API_BASE_URL=https://votre-domaine.com
ALLOWED_ORIGINS=https://votre-domaine.com,http://localhost:3000
```

### Sécurité

Ajoutez ces middlewares de sécurité dans `server.js` :

```javascript
const helmet = require('helmet');
const compression = require('compression');

app.use(helmet());
app.use(compression());

// Rate limiting
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limite à 100 requêtes par fenêtre
});
app.use('/api/', limiter);
```

### Sauvegarde automatique

Script de sauvegarde (`backup.sh`) :

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/path/to/backups"
DB_FILE="/path/to/dictionary.db"

# Créer le dossier de sauvegarde
mkdir -p $BACKUP_DIR

# Sauvegarder la base de données
cp $DB_FILE "$BACKUP_DIR/dictionary_backup_$DATE.db"

# Garder seulement les 30 dernières sauvegardes
find $BACKUP_DIR -name "dictionary_backup_*.db" -mtime +30 -delete

echo "Sauvegarde créée: dictionary_backup_$DATE.db"
```

Ajoutez dans crontab pour automatiser :

```bash
# Sauvegarde quotidienne à 2h du matin
0 2 * * * /path/to/backup.sh
```

## 📊 Monitoring et Logs

### Logs avec Winston

```bash
npm install winston
```

```javascript
// Ajout dans server.js
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ],
});
```

### Monitoring des performances

```javascript
// Middleware de monitoring
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info({
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`
    });
  });
  
  next();
});
```

## 🔄 Workflow de Développement

### 1. Environnement de développement

```bash
# Terminal 1: Backend
npm run dev

# Terminal 2: Flutter (si développement mobile)
flutter run

# Terminal 3: Tests
npm test
```

### 2. Tests automatisés

Créez `tests/api.test.js` :

```javascript
const request = require('supertest');
const app = require('../server');

describe('API Tests', () => {
  test('GET /api/words should return words array', async () => {
    const response = await request(app)
      .get('/api/words')
      .expect(200);
    
    expect(response.body).toHaveProperty('words');
    expect(Array.isArray(response.body.words)).toBe(true);
  });
  
  test('POST /api/words should create a new word', async () => {
    const newWord = {
      zarmaWord: 'test',
      zarmaExample: 'Test example',
      frenchMeaning: 'test',
      frenchExample: 'Exemple de test'
    };
    
    const response = await request(app)
      .post('/api/words')
      .send(newWord)
      .expect(201);
    
    expect(response.body).toHaveProperty('id');
  });
});
```

### 3. CI/CD avec GitHub Actions

Créez `.github/workflows/deploy.yml` :

```yaml
name: Deploy to Production

on:
  push:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    - run: npm install
    - run: npm test

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Deploy to Heroku
      uses: akhileshns/heroku-deploy@v3.12.12
      with:
        heroku_api_key: ${{secrets.HEROKU_API_KEY}}
        heroku_app_name: "votre-app-dictionnaire-zarma"
        heroku_email: "votre-email@example.com"
```

## 🎯 Utilisation

### Interface Web d'Administration
1. Accédez à `https://votre-domaine.com`
2. Utilisez l'interface pour ajouter, modifier et gérer les mots
3. Les données sont automatiquement synchronisées avec la base de données

### Application Mobile
1. L'application télécharge les mots lors de la première utilisation
2. Fonctionne hors ligne après le téléchargement initial
3. Se synchronise automatiquement quand une connexion est disponible
4. Les utilisateurs peuvent forcer une synchronisation dans les paramètres

### API REST
- `GET /api/words` - Liste tous les mots
- `POST /api/words` - Ajouter un nouveau mot
- `PUT /api/words/:id` - Modifier un mot
- `DELETE /api/words/:id` - Supprimer un mot
- `POST /api/sync` - Synchronisation pour l'application mobile

## 🔍 Résolution des Problèmes Courants

### Erreur de connexion à la base de données
```bash
# Vérifier les permissions
chmod 664 dictionary.db
chown www-data:www-data dictionary.db
```

### Application mobile ne peut pas se connecter
1. Vérifiez que l'URL de l'API est correcte dans `ApiService`
2. Vérifiez les permissions réseau
3. Testez l'URL dans un navigateur : `https://votre-domaine.com/api/words`

### Synchronisation bloquée
1. Réinitialisez le statut de sync : utilisez `resetSyncStatus()` dans l'app
2. Vérifiez les logs du serveur
3. Testez la connectivité réseau

## 🚀 Mise en Production

### Liste de vérification finale

- [ ] Tests complets de l'API
- [ ] Tests de l'interface web
- [ ] Tests de synchronisation mobile
- [ ] Configuration des sauvegardes
- [ ] Configuration des logs
- [ ] Monitoring activé
- [ ] SSL/HTTPS configuré
- [ ] Variables d'environnement sécurisées
- [ ] Rate limiting activé

Cette solution vous donne un système complet avec interface web d'administration, API robuste, et synchronisation mobile pour une expérience utilisateur optimale en mode hors ligne.