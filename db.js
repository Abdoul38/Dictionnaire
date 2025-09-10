// db.js - Configuration robuste de la base de données
const { Pool } = require('pg');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');
const logger = require('./logger');

class Database {
    constructor() {
        this.type = process.env.DB_TYPE || 'sqlite';
        this.init();
    }

    init() {
        if (this.type === 'postgres') {
            this.initPostgres();
        } else {
            this.initSQLite();
        }
    }

    initPostgres() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL || this.buildConnectionString(),
            ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
            max: parseInt(process.env.DB_POOL_MAX) || 20,
            idleTimeoutMillis: parseInt(process.env.DB_POOL_IDLE_TIMEOUT_MS) || 30000,
            connectionTimeoutMillis: parseInt(process.env.DB_POOL_CONNECTION_TIMEOUT_MS) || 2000,
        });

        // Gestion des erreurs de connexion
        this.pool.on('error', (err) => {
            logger.error('Erreur inattendue sur le client PostgreSQL', err);
        });

        // Test de connexion périodique pour maintenir la connexion active
        setInterval(async () => {
            try {
                await this.pool.query('SELECT 1');
            } catch (error) {
                logger.warn('Test de connexion PostgreSQL échoué', error);
            }
        }, parseInt(process.env.DB_RECONNECT_INTERVAL) || 60000);
    }

    buildConnectionString() {
        if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
        
        return `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`;
    }

    initSQLite() {
        this.db = new sqlite3.Database(process.env.DB_PATH || './dictionary.db', (err) => {
            if (err) {
                logger.error('Erreur de connexion SQLite', err);
            } else {
                logger.info('Connecté à la base de données SQLite');
                this.enableWAL(); // Améliore les performances
            }
        });

        // Promisify les méthodes pour utiliser async/await
        this.db.run = promisify(this.db.run).bind(this.db);
        this.db.get = promisify(this.db.get).bind(this.db);
        this.db.all = promisify(this.db.all).bind(this.db);
        this.db.exec = promisify(this.db.exec).bind(this.db);
    }

    enableWAL() {
        // Mode Write-Ahead Logging pour de meilleures performances
        this.db.run('PRAGMA journal_mode = WAL;');
        this.db.run('PRAGMA synchronous = NORMAL;');
        this.db.run('PRAGMA cache_size = -10000;'); // 10MB cache
    }

    async query(sql, params = []) {
        if (this.type === 'postgres') {
            try {
                const result = await this.pool.query(sql, params);
                return result.rows;
            } catch (error) {
                logger.error('Erreur de requête PostgreSQL', error);
                throw error;
            }
        } else {
            try {
                return await this.db.all(sql, params);
            } catch (error) {
                logger.error('Erreur de requête SQLite', error);
                throw error;
            }
        }
    }

    async get(sql, params = []) {
        if (this.type === 'postgres') {
            try {
                const result = await this.pool.query(sql, params);
                return result.rows[0] || null;
            } catch (error) {
                logger.error('Erreur de requête PostgreSQL', error);
                throw error;
            }
        } else {
            try {
                return await this.db.get(sql, params);
            } catch (error) {
                logger.error('Erreur de requête SQLite', error);
                throw error;
            }
        }
    }

    async run(sql, params = []) {
        if (this.type === 'postgres') {
            try {
                const result = await this.pool.query(sql, params);
                return { changes: result.rowCount, lastID: null };
            } catch (error) {
                logger.error('Erreur d\'exécution PostgreSQL', error);
                throw error;
            }
        } else {
            try {
                const result = await this.db.run(sql, params);
                return { changes: result.changes, lastID: result.lastID };
            } catch (error) {
                logger.error('Erreur d\'exécution SQLite', error);
                throw error;
            }
        }
    }

    // Méthode pour vérifier la connexion
    async healthCheck() {
        try {
            if (this.type === 'postgres') {
                await this.pool.query('SELECT 1');
            } else {
                await this.db.get('SELECT 1');
            }
            return true;
        } catch (error) {
            logger.error('Health check failed', error);
            return false;
        }
    }

    // Méthode pour fermer proprement la connexion
    async close() {
        if (this.type === 'postgres') {
            await this.pool.end();
        } else {
            await new Promise((resolve, reject) => {
                this.db.close((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }
    }
}

module.exports = new Database();