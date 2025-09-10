// middleware/dbMiddleware.js
const db = require('../db');
const logger = require('../logger');

async function dbConnectionMiddleware(req, res, next) {
    try {
        // Teste la connexion à la base de données
        const isConnected = await db.healthCheck();
        
        if (!isConnected) {
            logger.warn('Tentative de reconnexion à la base de données');
            // Réinitialise la connexion
            await db.close();
            db.init();
            
            // Vérifie à nouveau
            const reconnected = await db.healthCheck();
            if (!reconnected) {
                return res.status(503).json({ 
                    success: false, 
                    message: 'Service temporairement indisponible' 
                });
            }
        }
        
        next();
    } catch (error) {
        logger.error('Erreur dans le middleware de connexion BD', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erreur interne du serveur' 
        });
    }
}

module.exports = dbConnectionMiddleware;