@echo off
echo ====================================
echo  DICTIONNAIRE ZARMA - CREATION PROJET
echo ====================================
echo.

REM Vérifier si Node.js est installé
node --version >nul 2>&1
if errorlevel 1 (
    echo ERREUR: Node.js n'est pas installe ou pas dans le PATH
    echo Veuillez installer Node.js depuis https://nodejs.org/
    pause
    exit /b 1
)

REM Créer le dossier principal du projet
set PROJECT_NAME=dictionnaire-zarma-api
echo Creation du dossier principal: %PROJECT_NAME%
if not exist "%PROJECT_NAME%" (
    mkdir "%PROJECT_NAME%"
) else (
    echo Le dossier %PROJECT_NAME% existe deja.
)

cd "%PROJECT_NAME%"

REM Créer la structure des dossiers
echo.
echo Creation de la structure des dossiers...

REM Dossiers principaux
if not exist "config" mkdir "config"
if not exist "utils" mkdir "utils"
if not exist "middleware" mkdir "middleware"
if not exist "public" mkdir "public"
if not exist "uploads" mkdir "uploads"
if not exist "logs" mkdir "logs"
if not exist "backups" mkdir "backups"
if not exist "temp" mkdir "temp"
if not exist "templates" mkdir "templates"
if not exist "templates\emails" mkdir "templates\emails"
if not exist "tests" mkdir "tests"
if not exist "tests\unit" mkdir "tests\unit"
if not exist "tests\integration" mkdir "tests\integration"
if not exist "tests\fixtures" mkdir "tests\fixtures"
if not exist "tests\helpers" mkdir "tests\helpers"
if not exist "docs" mkdir "docs"
if not exist "scripts" mkdir "scripts"
if not exist "docker" mkdir "docker"

echo   [OK] Dossiers crees avec succes

REM Créer les fichiers .gitkeep pour les dossiers vides
echo.
echo Creation des fichiers .gitkeep...
echo. > "uploads\.gitkeep"
echo. > "temp\.gitkeep"
echo. > "logs\.gitkeep"
echo. > "backups\.gitkeep"

REM Créer le fichier .gitignore
echo.
echo Creation du fichier .gitignore...
(
echo node_modules/
echo .env
echo *.log
echo uploads/*
echo !uploads/.gitkeep
echo backups/*.db
echo temp/*
echo !temp/.gitkeep
echo .DS_Store
echo *.sqlite
echo *.db
echo coverage/
echo dist/
echo .nyc_output/
echo npm-debug.log*
echo yarn-debug.log*
echo yarn-error.log*
) > ".gitignore"

REM Créer le package.json
echo.
echo Creation du package.json...
(
echo {
echo   "name": "dictionnaire-zarma-api",
echo   "version": "1.0.0",
echo   "description": "API backend securisee pour le Dictionnaire Zarma avec authentification",
echo   "main": "server.js",
echo   "scripts": {
echo     "start": "node server.js",
echo     "dev": "nodemon server.js",
echo     "test": "jest",
echo     "test:coverage": "jest --coverage",
echo     "lint": "eslint .",
echo     "setup": "node setup.js",
echo     "migrate": "node scripts/migrate.js",
echo     "backup": "node scripts/backup.js",
echo     "seed": "node scripts/seed.js"
echo   },
echo   "keywords": [
echo     "dictionnaire",
echo     "zarma",
echo     "api",
echo     "authentification",
echo     "sqlite",
echo     "express"
echo   ],
echo   "author": "Dictionnaire Zarma Team",
echo   "license": "MIT",
echo   "dependencies": {
echo     "express": "^4.18.2",
echo     "cors": "^2.8.5",
echo     "sqlite3": "^5.1.6",
echo     "bcrypt": "^5.1.1",
echo     "jsonwebtoken": "^9.0.2",
echo     "express-rate-limit": "^6.10.0",
echo     "helmet": "^7.0.0",
echo     "multer": "^1.4.5-lts.1",
echo     "express-validator": "^7.0.1",
echo     "dotenv": "^16.3.1"
echo   },
echo   "devDependencies": {
echo     "nodemon": "^3.0.1",
echo     "jest": "^29.6.2",
echo     "supertest": "^6.3.3",
echo     "eslint": "^8.47.0"
echo   },
echo   "engines": {
echo     "node": ">=16.0.0"
echo   }
echo }
) > "package.json"

REM Créer le fichier .env.example
echo.
echo Creation du fichier .env.example...
(
echo # Configuration du serveur
echo PORT=3000
echo NODE_ENV=development
echo.
echo # Securite JWT - CHANGEZ CETTE CLE EN PRODUCTION !
echo JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-with-at-least-32-characters
echo.
echo # CORS - Domaines autorises ^(separes par des virgules^)
echo ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,https://votre-domaine.com
echo.
echo # Base de donnees
echo DB_PATH=./dictionary.db
echo.
echo # Upload de fichiers
echo MAX_FILE_SIZE=10485760
echo UPLOAD_PATH=./uploads
echo.
echo # Rate limiting
echo LOGIN_RATE_LIMIT_MAX=5
echo LOGIN_RATE_LIMIT_WINDOW_MS=900000
echo API_RATE_LIMIT_MAX=100
echo API_RATE_LIMIT_WINDOW_MS=900000
echo.
echo # Sessions
echo ADMIN_SESSION_DURATION=8h
echo REMEMBER_SESSION_DURATION=30d
echo.
echo # Securite
echo BCRYPT_ROUNDS=12
echo.
echo # Logs
echo LOG_LEVEL=info
echo LOG_FILE=./logs/app.log
echo.
echo # Backup automatique
echo BACKUP_ENABLED=true
echo BACKUP_INTERVAL_HOURS=24
echo BACKUP_RETENTION_DAYS=30
echo BACKUP_PATH=./backups
echo.
echo # Administrateur par defaut
echo DEFAULT_ADMIN_USERNAME=admin
echo DEFAULT_ADMIN_EMAIL=admin@dictionnaire-zarma.com
echo DEFAULT_ADMIN_PASSWORD=admin123
) > ".env.example"

REM Créer un README basique
echo.
echo Creation du fichier README.md...
(
echo # Dictionnaire Zarma API
echo.
echo API backend securisee pour le Dictionnaire Zarma avec authentification complete.
echo.
echo ## Installation rapide
echo.
echo ```bash
echo npm install
echo npm run setup
echo npm run dev
echo ```
echo.
echo ## Acces
echo.
echo - Interface d'administration: http://localhost:3000
echo - API: http://localhost:3000/api
echo.
echo ### Identifiants par defaut
echo - Utilisateur: admin
echo - Mot de passe: admin123
echo.
echo ⚠️ **Important**: Changez ces identifiants apres la premiere connexion !
echo.
echo ## Documentation
echo.
echo Consultez le dossier `docs/` pour la documentation complete.
) > "README.md"

REM Créer les fichiers de documentation de base
echo.
echo Creation des fichiers de documentation...

echo # Documentation API > "docs\api.md"
echo # Guide de deploiement > "docs\deployment.md"
echo # Guide de securite > "docs\security.md"
echo # Guide de developpement > "docs\development.md"

REM Créer des templates d'emails basiques
echo ^<^!DOCTYPE html^> > "templates\emails\welcome.html"
echo ^<html^>^<body^>^<h1^>Bienvenue^<^/h1^>^<^/body^>^<^/html^> >> "templates\emails\welcome.html"

REM Créer des fichiers de test de base
echo.
echo Creation des fichiers de test...
echo // Tests unitaires pour l'authentification > "tests\unit\auth.test.js"
echo // Tests unitaires pour les mots > "tests\unit\words.test.js"
echo // Tests d'integration API > "tests\integration\api.test.js"
echo [] > "tests\fixtures\sample-words.json"

REM Créer des scripts utilitaires
echo.
echo Creation des scripts utilitaires...
echo // Script de migration > "scripts\migrate.js"
echo // Script de sauvegarde > "scripts\backup.js"
echo // Script de restauration > "scripts\restore.js"
echo // Script de donnees d'exemple > "scripts\seed.js"

REM Créer la configuration Docker
echo.
echo Creation de la configuration Docker...
(
echo FROM node:16-alpine
echo WORKDIR /app
echo COPY package*.json ./
echo RUN npm ci --only=production
echo COPY . .
echo EXPOSE 3000
echo CMD ["npm", "start"]
) > "docker\Dockerfile"

(
echo version: '3.8'
echo services:
echo   dictionnaire-zarma-api:
echo     build: .
echo     ports:
echo       - "3000:3000"
echo     environment:
echo       - NODE_ENV=production
echo     volumes:
echo       - ./data:/app/data
echo       - ./logs:/app/logs
) > "docker\docker-compose.yml"

REM Afficher un résumé
echo.
echo ====================================
echo   CREATION TERMINEE AVEC SUCCES !
echo ====================================
echo.
echo Structure creee dans: %CD%
echo.
echo Prochaines etapes:
echo   1. cd %PROJECT_NAME%
echo   2. npm install
echo   3. Copiez vos fichiers server.js, setup.js, etc.
echo   4. npm run setup
echo   5. npm run dev
echo.
echo Dossiers crees:
echo   - config/           ^(Configuration^)
echo   - utils/            ^(Utilitaires^)
echo   - middleware/       ^(Middlewares^)
echo   - public/           ^(Fichiers statiques^)
echo   - uploads/          ^(Fichiers uploades^)
echo   - logs/             ^(Logs^)
echo   - backups/          ^(Sauvegardes^)
echo   - tests/            ^(Tests^)
echo   - docs/             ^(Documentation^)
echo   - scripts/          ^(Scripts utilitaires^)
echo   - docker/           ^(Configuration Docker^)
echo.
echo Fichiers crees:
echo   - package.json      ^(Dependances npm^)
echo   - .env.example      ^(Template environnement^)
echo   - .gitignore        ^(Git ignore^)
echo   - README.md         ^(Documentation^)
echo.
echo Pour commencer:
echo   npm install
echo.

pause