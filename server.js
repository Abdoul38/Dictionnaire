// server.js - Version corrigée pour Render.com avec PostgreSQL
require('dotenv').config();
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
let wss = null;
const connectedClients = new Map();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// server.js - Ajoutez en haut du fichier après les imports
const admin = require('firebase-admin');


// Configuration Firebase Admin
try {
  const serviceAccountPath = path.join(__dirname, 'config', 'dictionnaire-zarma-firebase-adminsdk-fbsvc-ad2a95728a.json');
  
  if (fs.existsSync(serviceAccountPath)) {
    const serviceAccount = require(serviceAccountPath);
    
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      // Optionnel: Ajoutez votre projectId si nécessaire
      projectId: serviceAccount.project_id || 'dictionnaire-zarma'
    });
    
    console.log('✅ Firebase Admin initialisé avec succès');
  } else {
    console.warn('⚠️ Fichier de service account Firebase non trouvé. Les notifications push ne fonctionneront pas.');
    console.warn('📁 Chemin attendu:', serviceAccountPath);
  }
} catch (error) {
  console.error('❌ Erreur initialisation Firebase Admin:', error.message);
  console.warn('⚠️ Les notifications push ne fonctionneront pas sans configuration Firebase valide');
}
// ========================================
// server-updated.js - Corrections principales
// ========================================

// Remplacer les imports en haut du fichier server.js
const { pool, testConnection, healthCheck, handleDatabaseError, queryWithRetry } = require('./db-config');


// Middleware de gestion d'erreurs (à ajouter après les routes)
app.use(handleDatabaseError);
// Middleware de parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
// Fonction de surveillance de la connexion
async function startConnectionMonitoring() {
  console.log('🔍 Démarrage de la surveillance de la connexion PostgreSQL...');
  
  const monitorInterval = setInterval(async () => {
    const health = await healthCheck();
    
    if (!health.healthy) {
      console.error('⚠️ Base de données non disponible:', health.error);
      console.log('🔄 Tentative de reconnexion...');
      await testConnection();
    } else {
      console.log(`💚 DB OK - Connexions: ${health.totalConnections}, Inactives: ${health.idleConnections}, En attente: ${health.waitingCount}`);
    }
  }, 60000); // Vérification toutes les minutes
  
  // Nettoyer l'intervalle à l'arrêt
  process.on('SIGTERM', () => clearInterval(monitorInterval));
  process.on('SIGINT', () => clearInterval(monitorInterval));
}
// Initialiser WebSocket Server
function initializeWebSocket(server) {
  console.log('🔄 Initialisation du WebSocket Server...');
  
  // CORRECTION: Vérifier que le serveur HTTP est prêt
  if (!server || !server.listening) {
    console.error('❌ Serveur HTTP non prêt pour WebSocket');
    return;
  }
  
  try {
    wss = new WebSocket.Server({ 
      server, 
      path: '/api/ws',
      // CORRECTION: Ajouter des options pour la stabilité
      perMessageDeflate: false,
      maxPayload: 64 * 1024, // 64KB max
      clientTracking: true,
      verifyClient: (info) => {
        const origin = info.req.headers.origin;
        const userAgent = info.req.headers['user-agent'] || '';
        
        console.log(`🔍 Nouvelle connexion WebSocket:
        - Origin: ${origin}
        - IP: ${info.req.connection.remoteAddress}
        - User-Agent: ${userAgent.substring(0, 100)}...`);
        
        return true; // Accepter toutes les connexions
      }
    });

    app.post('/api/send-push-notification', authenticateToken, async (req, res) => {
  try {
    const { notificationId, targetDevices = 'all' } = req.body;
    
    // Récupérer la notification depuis PostgreSQL
    const notificationResult = await pool.query(`
      SELECT * FROM notifications WHERE id = $1
    `, [notificationId]);
    
    if (notificationResult.rows.length === 0) {
      return res.status(404).json({ error: 'Notification non trouvée' });
    }
    
    const notification = notificationResult.rows[0];
    
    // Récupérer les tokens FCM des devices cibles
    let devicesQuery = 'SELECT fcm_token FROM user_devices WHERE is_active = TRUE';
    const params = [];
    
    if (targetDevices !== 'all') {
      // Implémentez votre logique de ciblage spécifique
    }
    
    const devicesResult = await pool.query(devicesQuery, params);
    const tokens = devicesResult.rows.map(row => row.fcm_token).filter(token => token);
    
    if (tokens.length === 0) {
      return res.json({ 
        success: true, 
        message: 'Aucun device actif pour envoyer la notification' 
      });
    }
    
    // Préparer le message de notification
    const message = {
      notification: {
        title: notification.title,
        body: notification.message,
      },
      data: {
        notificationId: notification.id,
        type: notification.type,
        priority: notification.priority,
        timestamp: notification.created_at.toString(),
        click_action: 'FLUTTER_NOTIFICATION_CLICK'
      },
      tokens: tokens,
    };
    
    // Envoyer la notification
    const response = await admin.messaging().sendEachForMulticast(message);
    
    res.json({
      success: true,
      message: `Notification envoyée à ${response.successCount} appareils`,
      details: {
        successCount: response.successCount,
        failureCount: response.failureCount,
        notification: {
          id: notification.id,
          title: notification.title
        }
      }
    });
    
  } catch (error) {
    console.error('Erreur envoi notification push:', error);
    res.status(500).json({ 
      error: 'Erreur lors de l\'envoi de la notification push',
      details: error.message 
    });
  }
});

// Table pour stocker les tokens FCM des devices

    
    // CORRECTION: Gérer les événements du serveur WebSocket
    wss.on('error', (error) => {
      console.error('❌ Erreur WebSocket Server:', error);
    });
    
    wss.on('connection', (ws, req) => {
  const clientId = uuidv4();
  const clientIP = req.headers['x-forwarded-for'] || 
                   req.headers['x-real-ip'] || 
                   req.connection.remoteAddress ||
                   req.socket.remoteAddress;
  
  const clientInfo = {
    id: clientId,
    ip: clientIP,
    userAgent: req.headers['user-agent'] || 'Unknown',
    connectedAt: new Date(),
    lastPing: new Date(),
    isAlive: true
  };
  
  connectedClients.set(clientId, { ws, info: clientInfo });
  
  console.log(`🔗 Client WebSocket connecté: ${clientId} (Total: ${connectedClients.size})`);
  
  // CORRECTION : Envoyer immédiatement le message de bienvenue
  try {
    ws.send(JSON.stringify({
      type: 'welcome',
      message: 'Connexion WebSocket établie avec succès',
      clientId: clientId,
      serverTime: Date.now(),
      timestamp: Date.now()
    }));
    
    console.log(`✅ Message de bienvenue envoyé à ${clientId}`);
    
  } catch (error) {
    console.error(`❌ Erreur envoi bienvenue à ${clientId}:`, error);
  }
  
  // CORRECTION : Gérer les messages avec plus de robustesse
  ws.on('message', (message) => {
    try {
      clientInfo.lastPing = new Date();
      clientInfo.isAlive = true;
      
      const data = JSON.parse(message.toString());
      console.log(`📨 Message de ${clientId}:`, data);
      
      switch (data.type) {
        case 'ping':
          ws.send(JSON.stringify({ 
            type: 'pong', 
            timestamp: Date.now(),
            clientId: clientId
          }));
          console.log(`🏓 Pong envoyé à ${clientId}`);
          break;
          
        case 'heartbeat':
          ws.send(JSON.stringify({
            type: 'heartbeat_ack',
            timestamp: Date.now()
          }));
          break;
          
        case 'request_notifications':
          // NOUVEAU : Répondre aux demandes de notifications
          console.log(`📨 Demande de notifications de ${clientId}`);
          sendExistingNotificationsToClient(ws, clientId);
          break;
          
        default:
          console.log(`❓ Message inconnu de ${clientId}:`, data.type);
      }
      
    } catch (error) {
      console.error(`❌ Erreur parsing message de ${clientId}:`, error);
    }
  });
      // CORRECTION: Détecter les connexions mortes
      ws.on('pong', () => {
        clientInfo.isAlive = true;
        clientInfo.lastPing = new Date();
        console.log(`💓 Pong reçu de ${clientId}`);
      });
      
      ws.on('close', (code, reason) => {
        connectedClients.delete(clientId);
        console.log(`🔌 Client ${clientId} déconnecté:
        - Code: ${code}
        - Raison: ${reason}
        - Total clients: ${connectedClients.size}`);
      });
      
      ws.on('error', (error) => {
        console.error(`❌ Erreur WebSocket client ${clientId}:`, error);
        connectedClients.delete(clientId);
      });
    });
    
    // CORRECTION: Ajouter un système de nettoyage des connexions mortes
    const heartbeatInterval = setInterval(() => {
      connectedClients.forEach(({ ws, info }, clientId) => {
        if (!info.isAlive) {
          console.log(`💀 Connexion morte détectée: ${clientId}`);
          ws.terminate();
          connectedClients.delete(clientId);
          return;
        }
        
        // Marquer comme potentiellement mort
        info.isAlive = false;
        
        // Envoyer un ping
        try {
          ws.ping();
        } catch (error) {
          console.error(`❌ Erreur ping vers ${clientId}:`, error);
          connectedClients.delete(clientId);
        }
      });
    }, 30000); // Toutes les 30 secondes
    
    // Nettoyer l'intervalle à l'arrêt
    process.on('SIGTERM', () => clearInterval(heartbeatInterval));
    process.on('SIGINT', () => clearInterval(heartbeatInterval));
    
    console.log('✅ WebSocket Server initialisé sur /api/ws');
    console.log(`📊 Configuration:
    - Path: /api/ws
    - Max payload: 64KB
    - Heartbeat: 30s
    - Client tracking: activé`);
    
  } catch (error) {
    console.error('❌ Erreur initialisation WebSocket Server:', error);
    throw error;
  }
}

function broadcastNotification(notification) {
  if (!wss) {
    console.log('❌ WebSocket Server non initialisé');
    return 0;
  }
  
  const messageType = notification.isUpdate ? 'notification_updated' : 'notification';
  
  const message = JSON.stringify({
    type: messageType,
    data: {
      ...notification,
      timestamp: notification.timestamp || Date.now(),
      isHistorical: false
    },
    serverTime: Date.now()
  });
  
  let sentCount = 0;
  let errorCount = 0;
  const deadConnections = [];
  
  console.log(`📢 Diffusion notification "${notification.title}" à ${connectedClients.size} clients`);
  
  connectedClients.forEach(({ ws, info }, clientId) => {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(message);
        sentCount++;
        console.log(`✅ Notification envoyée à ${clientId} (${info.ip})`);
      } catch (error) {
        console.error(`❌ Erreur envoi à ${clientId}:`, error);
        deadConnections.push(clientId);
        errorCount++;
      }
    } else {
      console.log(`⚠️ Client ${clientId} dans état ${ws.readyState}, suppression`);
      deadConnections.push(clientId);
    }
  });
  
  // Nettoyer les connexions mortes
  deadConnections.forEach(clientId => {
    connectedClients.delete(clientId);
  });
  
  const result = {
    sent: sentCount,
    errors: errorCount,
    totalClients: connectedClients.size,
    notification: notification.title
  };
  
  console.log(`📊 Résultat diffusion:`, result);
  
  return sentCount;
}

app.get('/api/notifications-diagnostic', async (req, res) => {
  try {
    // Compter les notifications
    const totalResult = await pool.query('SELECT COUNT(*) FROM notifications');
    const activeResult = await pool.query('SELECT COUNT(*) FROM notifications WHERE expires_at > $1', 
      [Math.floor(Date.now() / 1000)]);
    
    // Récupérer quelques exemples
    const samplesResult = await pool.query(`
      SELECT id, title, type, priority, created_at, expires_at
      FROM notifications 
      WHERE expires_at > $1 
      ORDER BY created_at DESC 
      LIMIT 3
    `, [Math.floor(Date.now() / 1000)]);
    
    res.json({
      database: {
        total: parseInt(totalResult.rows[0].count),
        active: parseInt(activeResult.rows[0].count),
        samples: samplesResult.rows
      },
      websocket: {
        serverActive: !!wss,
        connectedClients: connectedClients.size,
        clientIds: Array.from(connectedClients.keys()).slice(0, 5)
      },
      server: {
        uptime: process.uptime(),
        timestamp: Date.now()
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/test-notifications-send', async (req, res) => {
  try {
    console.log('🧪 Test d\'envoi de notifications à tous les clients connectés');
    
    // Récupérer les notifications existantes
    const result = await pool.query(`
      SELECT *, 
             created_at * 1000 as timestamp,
             expires_at * 1000 as expires_at_ms
      FROM notifications 
      WHERE expires_at > $1 
      ORDER BY created_at DESC 
      LIMIT 5
    `, [Math.floor(Date.now() / 1000)]);
    
    if (result.rows.length === 0) {
      return res.json({
        success: false,
        message: 'Aucune notification à envoyer',
        connectedClients: connectedClients.size
      });
    }
    
    let totalSent = 0;
    
    // Envoyer chaque notification
    for (const row of result.rows) {
      const notification = {
        id: row.id,
        title: row.title,
        message: row.message,
        type: row.type,
        priority: row.priority,
        target: row.target,
        createdBy: row.created_by,
        timestamp: row.timestamp,
        expiresAt: row.expires_at_ms,
        isHistorical: false
      };
      
      const sent = broadcastNotification(notification);
      totalSent += sent;
      
      // Attendre un peu entre chaque notification
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    res.json({
      success: true,
      message: `Test terminé - ${totalSent} notifications envoyées`,
      notificationsSent: result.rows.length,
      totalTransmissions: totalSent,
      connectedClients: connectedClients.size
    });
    
  } catch (error) {
    console.error('❌ Erreur test notifications:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
app.get('/api/websocket/status', (req, res) => {
  res.json({
    wsServerActive: !!wss,
    connectedClients: connectedClients.size,
    clients: Array.from(connectedClients.keys())
  });
});


// Routes pour les notifications administrateur
// Corrections pour les notifications dans server.js

// 1. Corriger la route de création de notifications
app.post('/api/admin/notifications', authenticateToken, async (req, res) => {
  try {
    // Vérifier le corps de la requête
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(400).json({ error: 'Corps de la requête manquant' });
    }
    
    const { title, message, type, priority, target, expiresAt } = req.body;
    
    // Validation
    if (!title || !message) {
      return res.status(400).json({ error: 'Titre et message requis' });
    }
    
    // Vérifier l'authentification
    if (!req.user || !req.user.username) {
      return res.status(401).json({ error: 'Utilisateur non authentifié' });
    }
    
    const notification = {
      id: uuidv4(), // Assurer que uuid est disponible
      title,
      message,
      type: type || 'info',
      priority: priority || 'normal',
      target: target || 'all',
      createdAt: Date.now(), // Utiliser timestamp en millisecondes pour le WebSocket
      expiresAt: expiresAt || (Date.now() + (7 * 24 * 60 * 60 * 1000)), // 7 jours en ms
      createdBy: req.user.username
    };
    
    // Sauvegarder dans la base (convertir en secondes pour PostgreSQL)
    await pool.query(`
      INSERT INTO notifications (id, title, message, type, priority, target, created_by, created_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [
      notification.id,
      notification.title,
      notification.message,
      notification.type,
      notification.priority,
      notification.target,
      notification.createdBy,
      Math.floor(notification.createdAt / 1000), // Convertir en secondes pour DB
      Math.floor(notification.expiresAt / 1000)  // Convertir en secondes pour DB
    ]);
    
    // Diffuser en temps réel
    const sentCount = broadcastNotification(notification);
    
    res.json({
      success: true,
      message: `Notification créée et diffusée à ${sentCount} clients`,
      notification
    });
    
  } catch (error) {
    console.error('Erreur création notification:', error);
    res.status(500).json({ 
      error: 'Erreur lors de la création de la notification',
      details: error.message 
    });
  }
});

// 2. Corriger la route de récupération des notifications
app.get('/api/notifications', async (req, res) => {
  const { limit = 20, offset = 0 } = req.query;
  
  try {
    const result = await pool.query(`
      SELECT *, 
             created_at * 1000 as timestamp,  -- Convertir en millisecondes
             expires_at * 1000 as expires_at_ms
      FROM notifications 
      WHERE expires_at > $1 
      ORDER BY created_at DESC 
      LIMIT $2 OFFSET $3
    `, [Math.floor(Date.now() / 1000), parseInt(limit), parseInt(offset)]);
    
    const notifications = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      message: row.message,
      type: row.type,
      priority: row.priority,
      target: row.target,
      createdBy: row.created_by,
      timestamp: row.timestamp, // En millisecondes pour le client
      expiresAt: row.expires_at_ms,
      createdAt: row.created_at
    }));
    
    res.json({ 
      notifications,
      total: notifications.length 
    });
  } catch (error) {
    console.error('Erreur récupération notifications:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des notifications' });
  }
});

// 3. Améliorer la fonction de diffusion WebSocket

// 4. Route pour tester les notifications
app.post('/api/test-notification', async (req, res) => {
  try {
    const testNotification = {
      id: uuidv4(),
      title: 'Test Notification',
      message: 'Ceci est une notification de test',
      type: 'info',
      priority: 'normal',
      target: 'all',
      createdAt: Date.now(),
      expiresAt: Date.now() + (24 * 60 * 60 * 1000), // 24h
      createdBy: 'system'
    };
    
    const sentCount = broadcastNotification(testNotification);
    
    res.json({
      success: true,
      message: `Notification de test envoyée à ${sentCount} clients`,
      notification: testNotification
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


async function sendExistingNotificationsToClient(ws, clientId) {
  try {
    console.log(`📬 Envoi notifications historiques à ${clientId}`);
    
    if (ws.readyState !== WebSocket.OPEN) {
      console.log(`❌ Client ${clientId} non connecté, annulation envoi`);
      return;
    }
    
    const result = await pool.query(`
      SELECT *, 
             created_at * 1000 as timestamp,
             expires_at * 1000 as expires_at_ms
      FROM notifications 
      WHERE expires_at > $1 
      ORDER BY created_at DESC 
      LIMIT 10
    `, [Math.floor(Date.now() / 1000)]);
    
    if (result.rows.length === 0) {
      console.log(`📭 Aucune notification historique pour ${clientId}`);
      
      // Envoyer un message confirmant qu'il n'y a pas de notifications
      ws.send(JSON.stringify({
        type: 'notifications_history',
        data: [],
        message: 'Aucune notification disponible',
        timestamp: Date.now()
      }));
      return;
    }
    
    console.log(`📨 ${result.rows.length} notifications à envoyer à ${clientId}`);
    
    // CORRECTION : Envoyer toutes les notifications en une seule fois
    const notifications = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      message: row.message,
      type: row.type,
      priority: row.priority,
      target: row.target,
      createdBy: row.created_by,
      timestamp: row.timestamp, // En millisecondes
      expiresAt: row.expires_at_ms,
      createdAt: row.created_at,
      isHistorical: true
    }));
    
    // Envoyer l'historique complet
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'notifications_history',
          data: notifications,
          count: notifications.length,
          timestamp: Date.now()
        }));
        
        console.log(`✅ ${notifications.length} notifications historiques envoyées à ${clientId}`);
        
        // Puis envoyer chaque notification individuellement pour déclencher les alertes
        setTimeout(() => {
          notifications.slice(0, 3).forEach((notification, index) => {
            setTimeout(() => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                  type: 'notification',
                  data: notification,
                  serverTime: Date.now()
                }));
                console.log(`🔔 Notification individuelle #${index+1} envoyée: "${notification.title}"`);
              }
            }, index * 500); // Délai de 500ms entre chaque notification
          });
        }, 1000);
        
      } else {
        console.log(`❌ Client ${clientId} déconnecté pendant l'envoi`);
      }
    } catch (error) {
      console.error(`❌ Erreur envoi notifications à ${clientId}:`, error);
    }
    
  } catch (error) {
    console.error(`❌ Erreur chargement notifications historiques pour ${clientId}:`, error);
    
    // Envoyer une notification d'erreur
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Erreur lors du chargement des notifications',
          timestamp: Date.now()
        }));
      }
    } catch (sendError) {
      console.error(`❌ Erreur envoi message d'erreur:`, sendError);
    }
  }
}
app.get('/api/websocket/diagnostic', (req, res) => {
  const diagnostics = {
    server: {
      initialized: !!wss,
      listening: wss ? wss.address() : null,
      clientCount: connectedClients.size
    },
    clients: []
  };
  
  if (connectedClients.size > 0) {
    connectedClients.forEach(({ ws, info }, clientId) => {
      diagnostics.clients.push({
        id: clientId.substring(0, 8) + '...',
        ip: info.ip,
        state: ws.readyState,
        stateText: ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'][ws.readyState],
        connectedAt: info.connectedAt,
        lastPing: info.lastPing,
        isAlive: info.isAlive,
        userAgent: info.userAgent.substring(0, 50) + '...'
      });
    });
  }
  
  res.json(diagnostics);
});


// Récupérer l'historique des notifications
app.get('/api/notifications', async (req, res) => {
  const { limit = 20, offset = 0 } = req.query;
  
  try {
    console.log(`📨 API notifications appelée - limit: ${limit}, offset: ${offset}`);
    
    const result = await pool.query(`
      SELECT *, 
             created_at * 1000 as timestamp,
             expires_at * 1000 as expires_at_ms
      FROM notifications 
      WHERE expires_at > $1 
      ORDER BY created_at DESC 
      LIMIT $2 OFFSET $3
    `, [Math.floor(Date.now() / 1000), parseInt(limit), parseInt(offset)]);
    
    const notifications = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      message: row.message,
      type: row.type,
      priority: row.priority,
      target: row.target,
      createdBy: row.created_by,
      timestamp: row.timestamp, // En millisecondes pour le client
      expiresAt: row.expires_at_ms,
      createdAt: row.created_at
    }));
    
    console.log(`✅ ${notifications.length} notifications renvoyées par l'API`);
    
    res.json({ 
      notifications,
      total: notifications.length,
      success: true
    });
  } catch (error) {
    console.error('❌ Erreur récupération notifications:', error);
    res.status(500).json({ 
      error: 'Erreur lors de la récupération des notifications',
      success: false 
    });
  }
});

// Marquer une notification comme lue
app.post('/api/notifications/:id/read', async (req, res) => {
  const { id } = req.params;
  const { deviceId } = req.body;
  
  try {
    await pool.query(`
      INSERT INTO notification_reads (notification_id, device_id, read_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (notification_id, device_id) DO NOTHING
    `, [id, deviceId || 'unknown', Math.floor(Date.now() / 1000)]);
    
    res.json({ success: true, message: 'Notification marquée comme lue' });
  } catch (error) {
    console.error('Erreur marquage notification:', error);
    res.status(500).json({ error: 'Erreur lors du marquage de la notification' });
  }
});

// Stats des notifications
app.get('/api/admin/notifications/stats', async (req, res) => {
  try {
    const totalResult = await pool.query('SELECT COUNT(*) FROM notifications');
    const activeResult = await pool.query('SELECT COUNT(*) FROM notifications WHERE expires_at > $1', 
      [Math.floor(Date.now() / 1000)]);
    const readsResult = await pool.query('SELECT COUNT(DISTINCT device_id) FROM notification_reads');
    
    res.json({
      total: parseInt(totalResult.rows[0].count),
      active: parseInt(activeResult.rows[0].count),
      uniqueDevices: parseInt(readsResult.rows[0].count)
    });
  } catch (error) {
    console.error('Erreur stats notifications:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
  }
});
// Route de santé améliorée
app.get('/health', async (req, res) => {
  try {
    const dbHealth = await healthCheck();
    
    res.status(dbHealth.healthy ? 200 : 503).json({
      status: dbHealth.healthy ? 'OK' : 'ERROR',
      timestamp: new Date().toISOString(),
      database: dbHealth,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV || 'production'
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// Exemple de route corrigée avec gestion d'erreurs
app.get('/api/words', async (req, res) => {
  const { search, category, difficulty, limit, offset } = req.query;
  
  let query = `
    SELECT w.*, 
           COALESCE(lp.view_count, 0) as view_count, 
           COALESCE(lp.practice_count, 0) as practice_count, 
           COALESCE(lp.is_learned, false) as is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) > 0 as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE 1=1
  `;
  
  const params = [];
  let paramCount = 0;
  
  if (search) {
    paramCount++;
    query += ` AND (w.zarma_word ILIKE $${paramCount} OR w.french_meaning ILIKE $${paramCount} OR w.zarma_example ILIKE $${paramCount} OR w.french_example ILIKE $${paramCount})`;
    params.push(`%${search}%`);
  }
  
  if (category) {
    paramCount++;
    query += ` AND w.category = $${paramCount}`;
    params.push(category);
  }
  
  if (difficulty) {
    paramCount++;
    query += ` AND w.difficulty_level = $${paramCount}`;
    params.push(difficulty);
  }
  
  query += ` ORDER BY w.usage_frequency DESC, w.zarma_word ASC`;
  
  if (limit) {
    paramCount++;
    query += ` LIMIT $${paramCount}`;
    params.push(parseInt(limit));
    
    if (offset) {
      paramCount++;
      query += ` OFFSET $${paramCount}`;
      params.push(parseInt(offset));
    }
  }
  
  try {
    // Utiliser queryWithRetry au lieu de pool.query directement
    const result = await queryWithRetry(query, params);
    
    const words = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      viewCount: row.view_count,
      practiceCount: row.practice_count,
      isLearned: row.is_learned,
      isFavorite: row.is_favorite
    }));
    
    res.json({ words, total: words.length });
  } catch (error) {
    console.error('Erreur lors de la récupération des mots:', error);
    
    // Laisser le middleware de gestion d'erreurs traiter cela
    next(error);
  }
});

// Fonction de démarrage du serveur mise à jour
async function startServer() {
  try {
    // Initialiser la base de données
    await initializeDatabase();
    
    // Démarrer la surveillance de la connexion DB
    await startConnectionMonitoring();
    
    // Démarrer le serveur HTTP
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur API Dictionnaire Zarma démarré sur le port ${PORT}`);
      console.log(`🔗 API disponible sur: https://dictionnaire-zarma-api.onrender.com/api`);
      console.log(`🔒 Authentification requise pour les routes d'administration`);
      console.log(`💾 Base de données: PostgreSQL`);
      console.log(`🌐 Environnement: ${process.env.NODE_ENV || 'production'}`);
    });

    // CORRECTION: Attendre que le serveur soit prêt avant d'initialiser WebSocket
    server.on('listening', () => {
      console.log('🎧 Serveur HTTP en écoute - Initialisation WebSocket...');
      try {
        initializeWebSocket(server);
      } catch (error) {
        console.error('❌ Erreur initialisation WebSocket:', error);
      }
    });
    
    // Gestion de l'arrêt propre du serveur
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} reçu, arrêt propre du serveur...`);
      
      // Fermer les connexions WebSocket
      if (wss) {
        console.log('🔄 Fermeture des connexions WebSocket...');
        
        // Notifier les clients de la fermeture
        const closeMessage = JSON.stringify({
          type: 'server_shutdown',
          message: 'Serveur en cours d\'arrêt',
          timestamp: Date.now()
        });
        
        connectedClients.forEach(({ ws }, clientId) => {
          if (ws.readyState === WebSocket.OPEN) {
            try {
              ws.send(closeMessage);
            } catch (error) {
              console.error(`Erreur notification fermeture ${clientId}:`, error);
            }
          }
        });
        
        // Attendre un peu pour que les messages soient envoyés
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        wss.close(() => {
          console.log('🔌 WebSocket Server fermé');
        });
      }
      
      server.close(async () => {
        console.log('🔴 Serveur HTTP fermé');
        try {
          await pool.end();
          console.log('✅ Connexions PostgreSQL fermées proprement');
        } catch (error) {
          console.error('Erreur lors de la fermeture des connexions:', error);
        }
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error);
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
}
// Configuration de la base de données PostgreSQL pour Render


// Configuration sécurisée
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const ADMIN_SESSION_DURATION = '8h';
const REMEMBER_SESSION_DURATION = '30d';

// Middleware de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Configuration CORS
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://172.18.2.199:3000', 
    'http://192.168.1.1:3000',
    'http://192.168.0.1:3000',
    'capacitor://localhost',
    'http://localhost',  
    'https://dictionnaire-zarma-api.onrender.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Middleware de logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} from ${req.ip}`);
  next();
});



// Créer le dossier uploads s'il n'existe pas
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configuration Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.json', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Type de fichier non supporté. Utilisez .json ou .csv'), false);
    }
  }
});

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limite à 5 tentatives
  message: {
    error: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.',
    lockoutTime: 15
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Trop de requêtes. Réessayez plus tard.'
  }
});

// Fonctions utilitaires
const parseCommaSeparated = (str) => {
  if (!str) return [];
  return str.split(',').map(s => s.trim()).filter(s => s.length > 0);
};

const joinCommaSeparated = (arr) => {
  if (!Array.isArray(arr)) return '';
  return arr.filter(s => s && s.trim()).join(',');
};

// Middleware d'authentification
// Middleware d'authentification corrigé
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: 'Token d\'accès requis',
      code: 'MISSING_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Vérifier si l'utilisateur existe toujours
    const userResult = await pool.query(
      'SELECT id, username, role, is_active FROM admin_users WHERE id = $1 AND is_active = TRUE',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Utilisateur non trouvé ou désactivé',
        code: 'USER_NOT_FOUND'
      });
    }

    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role
    };
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expiré',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({ 
      error: 'Token invalide',
      code: 'INVALID_TOKEN'
    });
  }
}

// Validation middleware
const validateWord = [
  body('zarmaWord').notEmpty().withMessage('Le mot zarma est requis'),
  body('frenchMeaning').notEmpty().withMessage('La signification française est requise'),
  body('zarmaExample').notEmpty().withMessage('L\'exemple zarma est requis'),
  body('frenchExample').notEmpty().withMessage('L\'exemple français est requis'),
  body('difficultyLevel').optional().isInt({ min: 1, max: 4 }).withMessage('Le niveau de difficulté doit être entre 1 et 4')
];

// Appliquer le rate limiting aux API
app.use('/api', apiLimiter);

// Routes de base
app.get('/api/test', (req, res) => {
  console.log('Route de test appelée depuis:', req.ip);
  res.json({
    success: true,
    message: 'API fonctionne avec PostgreSQL!',
    timestamp: new Date().toISOString(),
    database: 'PostgreSQL',
    client_ip: req.ip
  });
});

// PUT /api/admin/notifications/:id - Modifier une notification
app.put('/api/admin/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, message, type, priority, target, expiresAt } = req.body;
    
    // Validation
    if (!title || !message) {
      return res.status(400).json({ error: 'Titre et message requis' });
    }
    
    // Vérifier si la notification existe
    const notificationCheck = await pool.query(
      'SELECT id FROM notifications WHERE id = $1',
      [id]
    );
    
    if (notificationCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Notification non trouvée' });
    }
    
    // Mettre à jour la notification
    await pool.query(`
      UPDATE notifications 
      SET title = $1, message = $2, type = $3, priority = $4, 
          target = $5, expires_at = $6, updated_at = EXTRACT(EPOCH FROM NOW())
      WHERE id = $7
    `, [
      title,
      message,
      type || 'info',
      priority || 'normal',
      target || 'all',
      Math.floor((expiresAt || (Date.now() + (7 * 24 * 60 * 60 * 1000))) / 1000),
      id
    ]);
    
    // Récupérer la notification mise à jour
    const result = await pool.query(`
      SELECT *, 
             created_at * 1000 as timestamp,
             expires_at * 1000 as expires_at_ms
      FROM notifications 
      WHERE id = $1
    `, [id]);
    
    const updatedNotification = {
      id: result.rows[0].id,
      title: result.rows[0].title,
      message: result.rows[0].message,
      type: result.rows[0].type,
      priority: result.rows[0].priority,
      target: result.rows[0].target,
      createdBy: result.rows[0].created_by,
      timestamp: result.rows[0].timestamp,
      expiresAt: result.rows[0].expires_at_ms
    };
    
    // Diffuser la notification mise à jour
    const sentCount = broadcastNotification({
      ...updatedNotification,
      isUpdate: true
    });
    
    res.json({
      success: true,
      message: `Notification modifiée et diffusée à ${sentCount} clients`,
      notification: updatedNotification
    });
    
  } catch (error) {
    console.error('Erreur modification notification:', error);
    res.status(500).json({ 
      error: 'Erreur lors de la modification de la notification',
      details: error.message 
    });
  }
});

// DELETE /api/admin/notifications/:id - Supprimer une notification
app.delete('/api/admin/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Vérifier si la notification existe
    const notificationCheck = await pool.query(
      'SELECT id, title FROM notifications WHERE id = $1',
      [id]
    );
    
    if (notificationCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Notification non trouvée' });
    }
    
    const notificationTitle = notificationCheck.rows[0].title;
    
    // Supprimer la notification
    await pool.query('DELETE FROM notifications WHERE id = $1', [id]);
    
    // Diffuser un message de suppression
    const deletionMessage = {
      type: 'notification_deleted',
      notificationId: id,
      message: `Notification "${notificationTitle}" supprimée`,
      timestamp: Date.now()
    };
    
    let deletedCount = 0;
    connectedClients.forEach(({ ws }, clientId) => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify(deletionMessage));
          deletedCount++;
        } catch (error) {
          console.error(`Erreur envoi suppression à ${clientId}:`, error);
        }
      }
    });
    
    res.json({
      success: true,
      message: `Notification supprimée (notification envoyée à ${deletedCount} clients)`,
      notificationId: id
    });
    
  } catch (error) {
    console.error('Erreur suppression notification:', error);
    res.status(500).json({ 
      error: 'Erreur lors de la suppression de la notification',
      details: error.message 
    });
  }
});

// GET /api/admin/notifications/:id - Récupérer une notification spécifique
app.get('/api/admin/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(`
      SELECT *, 
             created_at * 1000 as timestamp,
             expires_at * 1000 as expires_at_ms
      FROM notifications 
      WHERE id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Notification non trouvée' });
    }
    
    const notification = result.rows[0];
    
    res.json({
      id: notification.id,
      title: notification.title,
      message: notification.message,
      type: notification.type,
      priority: notification.priority,
      target: notification.target,
      createdBy: notification.created_by,
      timestamp: notification.timestamp,
      expiresAt: notification.expires_at_ms,
      createdAt: notification.created_at
    });
    
  } catch (error) {
    console.error('Erreur récupération notification:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération de la notification' });
  }
});

// Routes d'authentification
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password, rememberMe } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Nom d\'utilisateur et mot de passe requis'
    });
  }

  try {
    // Recherche de l'utilisateur
    const userResult = await pool.query(
      'SELECT * FROM admin_users WHERE username = $1 AND is_active = TRUE',
      [username]
    );

    let loginSuccess = false;
    const user = userResult.rows[0];

    if (user && await bcrypt.compare(password, user.password_hash)) {
      loginSuccess = true;

      try {
        // Générer le token JWT
        const tokenPayload = {
          userId: user.id,
          username: user.username,
          role: user.role
        };

        const sessionDuration = rememberMe ? REMEMBER_SESSION_DURATION : ADMIN_SESSION_DURATION;
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: sessionDuration });
        
        // Calculer la date d'expiration en secondes
        const expirationSeconds = rememberMe ? 30 * 24 * 60 * 60 : 8 * 60 * 60;
        const expiresAt = Math.floor(Date.now() / 1000) + expirationSeconds;
        
        // Nettoyer les anciennes sessions expirées
        await pool.query('DELETE FROM admin_sessions WHERE expires_at < $1', [Math.floor(Date.now() / 1000)]);
        
        // Stocker la session dans la base
        await pool.query(
          'INSERT INTO admin_sessions (user_id, token_hash, ip_address, user_agent, expires_at, is_remember_me) VALUES ($1, $2, $3, $4, $5, $6)',
          [user.id, token.substring(0, 50), ipAddress, userAgent, expiresAt, rememberMe]
        );

        // Mettre à jour la dernière connexion
        await pool.query('UPDATE admin_users SET last_login = $1 WHERE id = $2', [Math.floor(Date.now() / 1000), user.id]);

        // Retourner la réponse de succès
        res.json({
          success: true,
          message: 'Connexion réussie',
          token: token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            email: user.email
          },
          expiresIn: sessionDuration,
          expiresAt: expiresAt
        });
      } catch (tokenError) {
        console.error('Erreur lors de la génération du token:', tokenError);
        return res.status(500).json({
          success: false,
          message: 'Erreur lors de la création du token'
        });
      }
    } else {
      // Connexion échouée
      res.status(401).json({
        success: false,
        message: 'Identifiants incorrects'
      });
    }

    // Enregistrer la tentative de connexion
    await pool.query(
      'INSERT INTO login_attempts (ip_address, username, success, user_agent) VALUES ($1, $2, $3, $4)',
      [ipAddress, username, loginSuccess, userAgent]
    );
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur interne du serveur'
    });
  }
});

// GET /api/quiz - Récupérer tous les quiz
app.get('/api/quiz', async (req, res) => {
  const { category, type, difficulty } = req.query;
  
  let query = `
    SELECT q.*, COUNT(qq.id) as question_count
    FROM quizzes q
    LEFT JOIN quiz_questions qq ON q.id = qq.quiz_id
    WHERE q.is_active = TRUE
  `;
  
  const params = [];
  let paramCount = 0;
  
  if (category) {
    paramCount++;
    query += ` AND q.category = $${paramCount}`;
    params.push(category);
  }
  
  if (type) {
    paramCount++;
    query += ` AND q.quiz_type = $${paramCount}`;
    params.push(type);
  }
  
  if (difficulty) {
    paramCount++;
    query += ` AND q.difficulty = $${paramCount}`;
    params.push(difficulty);
  }
  
  query += ` GROUP BY q.id ORDER BY q.created_at DESC`;
  
  try {
    const result = await pool.query(query, params);
    
    const quizzes = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      description: row.description,
      category: row.category,
      quizType: row.quiz_type,
      difficulty: row.difficulty,
      timeLimit: row.time_limit,
      primaryColor: row.primary_color,
      questionCount: parseInt(row.question_count),
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
    
    res.json({ quizzes, total: quizzes.length });
  } catch (error) {
    console.error('Erreur lors de la récupération des quiz:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des quiz' });
  }
});

// GET /api/quiz/:id - Récupérer un quiz spécifique avec ses questions
app.get('/api/quiz/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Récupérer les informations du quiz
    const quizResult = await pool.query('SELECT * FROM quizzes WHERE id = $1 AND is_active = TRUE', [id]);
    
    if (quizResult.rows.length === 0) {
      return res.status(404).json({ error: 'Quiz non trouvé' });
    }
    
    const quiz = quizResult.rows[0];
    
    // Récupérer les questions du quiz
    const questionsResult = await pool.query(`
      SELECT qq.*, 
             json_agg(
               json_build_object(
                 'id', qo.id,
                 'optionText', qo.option_text,
                 'isCorrect', qo.is_correct,
                 'order', qo.option_order
               ) ORDER BY qo.option_order
             ) as options
      FROM quiz_questions qq
      LEFT JOIN question_options qo ON qq.id = qo.question_id
      WHERE qq.quiz_id = $1
      GROUP BY qq.id
      ORDER BY qq.question_order
    `, [id]);
    
    const questions = questionsResult.rows.map(row => ({
      id: row.id,
      questionText: row.question_text,
      explanation: row.explanation,
      audioPath: row.audio_path,
      order: row.question_order,
      options: row.options.filter(opt => opt.optionText !== null)
    }));
    
    res.json({
      id: quiz.id,
      title: quiz.title,
      description: quiz.description,
      category: quiz.category,
      quizType: quiz.quiz_type,
      difficulty: quiz.difficulty,
      timeLimit: quiz.time_limit,
      primaryColor: quiz.primary_color,
      questions: questions,
      createdAt: quiz.created_at,
      updatedAt: quiz.updated_at
    });
  } catch (error) {
    console.error('Erreur lors de la récupération du quiz:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération du quiz' });
  }
});

// POST /api/quiz - Créer un nouveau quiz (protégé)
app.post('/api/quiz', async (req, res) => {
  const {
    title,
    description,
    category,
    quizType,
    difficulty,
    timeLimit = 30,
    primaryColor,
    questions
  } = req.body;
  
  // Validation de base
  if (!title || !description || !category || !quizType || !difficulty) {
    return res.status(400).json({ error: 'Tous les champs obligatoires doivent être remplis' });
  }
  
  if (!questions || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: 'Le quiz doit contenir au moins une question' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Insérer le quiz
    const quizResult = await client.query(`
      INSERT INTO quizzes (title, description, category, quiz_type, difficulty, time_limit, primary_color)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
    `, [title, description, category, quizType, difficulty, timeLimit, primaryColor]);
    
    const quizId = quizResult.rows[0].id;
    
    // Insérer les questions et options
    for (let i = 0; i < questions.length; i++) {
      const question = questions[i];
      
      const questionResult = await client.query(`
        INSERT INTO quiz_questions (quiz_id, question_text, explanation, audio_path, question_order)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
      `, [quizId, question.question, question.explanation, question.audioPath, i]);
      
      const questionId = questionResult.rows[0].id;
      
      // Insérer les options
      for (let j = 0; j < question.options.length; j++) {
        const option = question.options[j];
        
        await client.query(`
          INSERT INTO question_options (question_id, option_text, is_correct, option_order)
          VALUES ($1, $2, $3, $4)
        `, [questionId, option, j === question.correct, j]);
      }
    }
    
    await client.query('COMMIT');
    
    res.status(201).json({
      id: quizId,
      message: 'Quiz créé avec succès'
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur lors de la création du quiz:', error);
    res.status(500).json({ error: 'Erreur lors de la création du quiz' });
  } finally {
    client.release();
  }
});

// PUT /api/quiz/:id - Modifier un quiz (protégé)
app.put('/api/quiz/:id', async (req, res) => {
  const { id } = req.params;
  const {
    title,
    description,
    category,
    quizType,
    difficulty,
    timeLimit,
    primaryColor,
    questions
  } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Mettre à jour le quiz
    await client.query(`
      UPDATE quizzes 
      SET title = $1, description = $2, category = $3, quiz_type = $4, 
          difficulty = $5, time_limit = $6, primary_color = $7
      WHERE id = $8
    `, [title, description, category, quizType, difficulty, timeLimit, primaryColor, id]);
    
    // Supprimer les anciennes questions et options
    await client.query('DELETE FROM question_options WHERE question_id IN (SELECT id FROM quiz_questions WHERE quiz_id = $1)', [id]);
    await client.query('DELETE FROM quiz_questions WHERE quiz_id = $1', [id]);
    
    // Insérer les nouvelles questions et options
    for (let i = 0; i < questions.length; i++) {
      const question = questions[i];
      
      const questionResult = await client.query(`
        INSERT INTO quiz_questions (quiz_id, question_text, explanation, audio_path, question_order)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
      `, [id, question.question, question.explanation, question.audioPath, i]);
      
      const questionId = questionResult.rows[0].id;
      
      // Insérer les options
      for (let j = 0; j < question.options.length; j++) {
        const option = question.options[j];
        
        await client.query(`
          INSERT INTO question_options (question_id, option_text, is_correct, option_order)
          VALUES ($1, $2, $3, $4)
        `, [questionId, option, j === question.correct, j]);
      }
    }
    
    await client.query('COMMIT');
    
    res.json({ message: 'Quiz modifié avec succès' });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur lors de la modification du quiz:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du quiz' });
  } finally {
    client.release();
  }
});

// DELETE /api/quiz/:id - Supprimer un quiz (protégé)
app.delete('/api/quiz/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Utiliser CASCADE pour supprimer automatiquement les questions et options associées
    await pool.query('DELETE FROM quizzes WHERE id = $1', [id]);
    res.json({ message: 'Quiz supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression du quiz:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du quiz' });
  }
});

// Routes pour les exercices
// POST /api/exercise - Créer un nouvel exercice (protégé)
app.post('/api/exercise', async (req, res) => {
  const {
    title,
    description,
    type,
    primaryColor,
    items
  } = req.body;
  
  // Validation de base
  if (!title || !description || !type) {
    return res.status(400).json({ error: 'Tous les champs obligatoires doivent être remplis' });
  }
  
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'L\'exercice doit contenir au moins un élément' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Insérer l'exercice
    const exerciseResult = await client.query(`
      INSERT INTO exercises (title, description, exercise_type, primary_color)
      VALUES ($1, $2, $3, $4)
      RETURNING id
    `, [title, description, type, primaryColor]);
    
    const exerciseId = exerciseResult.rows[0].id;
    
    // Insérer les éléments
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      
      await client.query(`
        INSERT INTO exercise_items (exercise_id, zarma_text, french_text, tip, audio_path, item_order)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [exerciseId, item.zarmaText, item.frenchText, item.tip, item.audioPath, i]);
    }
    
    await client.query('COMMIT');
    
    res.status(201).json({
      id: exerciseId,
      message: 'Exercice créé avec succès'
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur lors de la création de l\'exercice:', error);
    res.status(500).json({ error: 'Erreur lors de la création de l\'exercice' });
  } finally {
    client.release();
  }
});

// GET /api/exercise - Récupérer tous les exercices
app.get('/api/exercise', async (req, res) => {
  const { type } = req.query;
  
  let query = `
    SELECT e.*, COUNT(ei.id) as item_count
    FROM exercises e
    LEFT JOIN exercise_items ei ON e.id = ei.exercise_id
    WHERE e.is_active = TRUE
  `;
  
  const params = [];
  let paramCount = 0;
  
  if (type) {
    paramCount++;
    query += ` AND e.exercise_type = $${paramCount}`;
    params.push(type);
  }
  
  query += ` GROUP BY e.id ORDER BY e.created_at DESC`;
  
  try {
    const result = await pool.query(query, params);
    
    const exercises = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      description: row.description,
      exerciseType: row.exercise_type,
      primaryColor: row.primary_color,
      itemCount: parseInt(row.item_count),
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
    
    res.json({ exercises, total: exercises.length });
  } catch (error) {
    console.error('Erreur lors de la récupération des exercices:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des exercices' });
  }
});

// GET /api/exercise/:id - Récupérer un exercice spécifique avec ses éléments
app.get('/api/exercise/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Récupérer les informations de l'exercice
    const exerciseResult = await pool.query('SELECT * FROM exercises WHERE id = $1 AND is_active = TRUE', [id]);
    
    if (exerciseResult.rows.length === 0) {
      return res.status(404).json({ error: 'Exercice non trouvé' });
    }
    
    const exercise = exerciseResult.rows[0];
    
    // Récupérer les éléments de l'exercice
    const itemsResult = await pool.query(`
      SELECT * FROM exercise_items 
      WHERE exercise_id = $1 
      ORDER BY item_order
    `, [id]);
    
    const items = itemsResult.rows.map(row => ({
      id: row.id,
      zarmaText: row.zarma_text,
      frenchText: row.french_text,
      tip: row.tip,
      audioPath: row.audio_path,
      order: row.item_order
    }));
    
    res.json({
      id: exercise.id,
      title: exercise.title,
      description: exercise.description,
      exerciseType: exercise.exercise_type,
      primaryColor: exercise.primary_color,
      items: items,
      createdAt: exercise.created_at,
      updatedAt: exercise.updated_at
    });
  } catch (error) {
    console.error('Erreur lors de la récupération de l\'exercice:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'exercice' });
  }
});

// PUT /api/exercise/:id - Modifier un exercice (protégé)
app.put('/api/exercise/:id', async (req, res) => {
  const { id } = req.params;
  const {
    title,
    description,
    type,
    primaryColor,
    items
  } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Mettre à jour l'exercice
    await client.query(`
      UPDATE exercises 
      SET title = $1, description = $2, exercise_type = $3, primary_color = $4
      WHERE id = $5
    `, [title, description, type, primaryColor, id]);
    
    // Supprimer les anciens éléments
    await client.query('DELETE FROM exercise_items WHERE exercise_id = $1', [id]);
    
    // Insérer les nouveaux éléments
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      
      await client.query(`
        INSERT INTO exercise_items (exercise_id, zarma_text, french_text, tip, audio_path, item_order)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [id, item.zarmaText, item.frenchText, item.tip, item.audioPath, i]);
    }
    
    await client.query('COMMIT');
    
    res.json({ message: 'Exercice modifié avec succès' });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur lors de la modification de l\'exercice:', error);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'exercice' });
  } finally {
    client.release();
  }
});

// DELETE /api/exercise/:id - Supprimer un exercice (protégé)
app.delete('/api/exercise/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Utiliser CASCADE pour supprimer automatiquement les éléments associés
    await pool.query('DELETE FROM exercises WHERE id = $1', [id]);
    res.json({ message: 'Exercice supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression de l\'exercice:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'exercice' });
  }
});

// Middleware d'authentification (doit être défini ailleurs dans votre application)
// Middleware d'authentification corrigé
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: 'Token d\'accès requis',
      code: 'MISSING_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Vérifier si l'utilisateur existe toujours
    const userResult = await pool.query(
      'SELECT id, username, role, is_active FROM admin_users WHERE id = $1 AND is_active = TRUE',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Utilisateur non trouvé ou désactivé',
        code: 'USER_NOT_FOUND'
      });
    }

    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role
    };
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expiré',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({ 
      error: 'Token invalide',
      code: 'INVALID_TOKEN'
    });
  }
}
// GET /api/auth/verify - Vérifier un token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token valide',
    user: req.user
  });
});
// POST /api/auth/logout - Déconnexion
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM admin_sessions WHERE token_hash LIKE $1', [
      req.headers['authorization']?.split(' ')[1]?.substring(0, 50) || ''
    ]);
    
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error('Erreur lors de la déconnexion:', error);
    res.status(500).json({ success: false, message: 'Erreur lors de la déconnexion' });
  }
});

// Routes pour les mots
// GET /api/words - Récupérer tous les mots avec filtres optionnels
app.get('/api/words', async (req, res) => {
  const { search, category, difficulty, limit, offset } = req.query;
  
  let query = `
    SELECT w.*, 
           COALESCE(lp.view_count, 0) as view_count, 
           COALESCE(lp.practice_count, 0) as practice_count, 
           COALESCE(lp.is_learned, false) as is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) > 0 as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
    WHERE 1=1
  `;
  
  const params = [];
  let paramCount = 0;
  
  if (search) {
    paramCount++;
    query += ` AND (w.zarma_word ILIKE $${paramCount} OR w.french_meaning ILIKE $${paramCount} OR w.zarma_example ILIKE $${paramCount} OR w.french_example ILIKE $${paramCount})`;
    params.push(`%${search}%`);
  }
  
  if (category) {
    paramCount++;
    query += ` AND w.category = $${paramCount}`;
    params.push(category);
  }
  
  if (difficulty) {
    paramCount++;
    query += ` AND w.difficulty_level = $${paramCount}`;
    params.push(difficulty);
  }
  
  query += ` ORDER BY w.usage_frequency DESC, w.zarma_word ASC`;
  
  if (limit) {
    paramCount++;
    query += ` LIMIT $${paramCount}`;
    params.push(parseInt(limit));
    
    if (offset) {
      paramCount++;
      query += ` OFFSET $${paramCount}`;
      params.push(parseInt(offset));
    }
  }
  
  try {
    const result = await pool.query(query, params);
    
    const words = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      viewCount: row.view_count,
      practiceCount: row.practice_count,
      isLearned: row.is_learned,
      isFavorite: row.is_favorite
    }));
    
    res.json({ words, total: words.length });
  } catch (error) {
    console.error('Erreur lors de la récupération des mots:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/words/:id - Récupérer un mot spécifique
app.get('/api/words/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT w.*, 
             COALESCE(lp.view_count, 0) as view_count, 
             COALESCE(lp.practice_count, 0) as practice_count, 
             COALESCE(lp.is_learned, false) as is_learned
      FROM words w 
      LEFT JOIN learning_progress lp ON w.id = lp.word_id
      WHERE w.id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }
    
    const word = result.rows[0];
    res.json({
      id: word.id,
      zarmaWord: word.zarma_word,
      zarmaExample: word.zarma_example,
      frenchMeaning: word.french_meaning,
      frenchExample: word.french_example,
      category: word.category,
      pronunciation: word.pronunciation,
      difficultyLevel: word.difficulty_level,
      etymology: word.etymology,
      synonyms: parseCommaSeparated(word.synonyms),
      antonyms: parseCommaSeparated(word.antonyms),
      relatedWords: parseCommaSeparated(word.related_words),
      usageFrequency: word.usage_frequency,
      audioPath: word.audio_path,
      imagePath: word.image_path,
      createdAt: word.created_at,
      updatedAt: word.updated_at,
      viewCount: word.view_count,
      practiceCount: word.practice_count,
      isLearned: word.is_learned
    });
  } catch (error) {
    console.error('Erreur lors de la récupération du mot:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/words - Créer un nouveau mot (protégé)
app.post('/api/words', authenticateToken, validateWord, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const {
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel, etymology,
    synonyms, antonyms, relatedWords
  } = req.body;
  
  try {
    const result = await pool.query(`
      INSERT INTO words (
        zarma_word, zarma_example, french_meaning, french_example,
        category, pronunciation, difficulty_level, etymology,
        synonyms, antonyms, related_words
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id
    `, [
      zarmaWord, zarmaExample, frenchMeaning, frenchExample,
      category, pronunciation, difficultyLevel || 1, etymology,
      joinCommaSeparated(synonyms),
      joinCommaSeparated(antonyms),
      joinCommaSeparated(relatedWords)
    ]);
    
    const wordId = result.rows[0].id;
    
    // Initialiser les progrès d'apprentissage
    await pool.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [wordId]);
    
    res.status(201).json({ 
      id: wordId, 
      message: 'Mot ajouté avec succès'
    });
  } catch (error) {
    console.error('Erreur lors de l\'ajout du mot:', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout du mot' });
  }
});

// PUT /api/words/:id - Modifier un mot (protégé)
app.put('/api/words/:id', authenticateToken, validateWord, async (req, res) => {
  const { id } = req.params;
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const {
    zarmaWord, zarmaExample, frenchMeaning, frenchExample,
    category, pronunciation, difficultyLevel, etymology,
    synonyms, antonyms, relatedWords
  } = req.body;
  
  try {
    await pool.query(`
      UPDATE words SET
        zarma_word = $1,
        zarma_example = $2,
        french_meaning = $3,
        french_example = $4,
        category = $5,
        pronunciation = $6,
        difficulty_level = $7,
        etymology = $8,
        synonyms = $9,
        antonyms = $10,
        related_words = $11,
        updated_at = EXTRACT(EPOCH FROM NOW())
      WHERE id = $12
    `, [
      zarmaWord, zarmaExample, frenchMeaning, frenchExample,
      category, pronunciation, difficultyLevel || 1, etymology,
      joinCommaSeparated(synonyms),
      joinCommaSeparated(antonyms),
      joinCommaSeparated(relatedWords),
      id
    ]);
    
    res.json({ message: 'Mot modifié avec succès' });
  } catch (error) {
    console.error('Erreur lors de la modification du mot:', error);
    res.status(500).json({ error: 'Erreur lors de la modification du mot' });
  }
});

// DELETE /api/words/:id - Supprimer un mot (protégé)
app.delete('/api/words/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    await pool.query('DELETE FROM words WHERE id = $1', [id]);
    res.json({ message: 'Mot supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression du mot:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression du mot' });
  }
});

// GET /api/stats - Statistiques du dictionnaire
app.get('/api/stats', async (req, res) => {
  try {
    // Statistiques de base
    const totalWordsResult = await pool.query('SELECT COUNT(*) as count FROM words');
    const totalWords = parseInt(totalWordsResult.rows[0].count);

    const categoriesResult = await pool.query('SELECT COUNT(DISTINCT category) as count FROM words WHERE category IS NOT NULL AND category != \'\'');
    const totalCategories = parseInt(categoriesResult.rows[0].count);

    const avgDifficultyResult = await pool.query('SELECT AVG(difficulty_level) as avg FROM words');
    const avgDifficulty = parseFloat(avgDifficultyResult.rows[0].avg || 0).toFixed(1);

    // Calcul du taux de complétion (mots avec tous les champs remplis)
    const completeWordsResult = await pool.query(`
      SELECT COUNT(*) as count FROM words 
      WHERE pronunciation IS NOT NULL AND pronunciation != ''
        AND etymology IS NOT NULL AND etymology != ''
        AND synonyms IS NOT NULL AND synonyms != ''
    `);
    const completeWords = parseInt(completeWordsResult.rows[0].count);
    const completionRate = totalWords > 0 ? Math.round((completeWords / totalWords) * 100) : 0;

    // Répartition par catégories
    const categoryDistributionResult = await pool.query(`
      SELECT category, COUNT(*) as count 
      FROM words 
      WHERE category IS NOT NULL AND category != ''
      GROUP BY category 
      ORDER BY count DESC
    `);

    const categoryDistribution = categoryDistributionResult.rows.map(row => ({
      category: row.category,
      count: parseInt(row.count)
    }));

    res.json({
      totalWords,
      totalCategories,
      avgDifficulty,
      completionRate,
      categoryDistribution
    });
  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
  }
});

// GET /api/export - Export des données
// Corrections pour les fonctions d'export et d'import dans server.js

// GET /api/export - Export des données (CORRIGÉ)
app.get('/api/export', async (req, res) => {
  const { format } = req.query;
  
  try {
    const result = await pool.query(`
      SELECT 
        zarma_word, french_meaning, zarma_example, french_example,
        category, pronunciation, difficulty_level, etymology,
        synonyms, antonyms, related_words, created_at, updated_at
      FROM words 
      ORDER BY zarma_word
    `);

    const words = result.rows.map(row => ({
      zarmaWord: row.zarma_word,
      frenchMeaning: row.french_meaning,
      zarmaExample: row.zarma_example,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: row.synonyms,
      antonyms: row.antonyms,
      relatedWords: row.related_words,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));

    if (format === 'csv') {
      // Export CSV avec encodage UTF-8
      let csv = '\uFEFF'; // BOM UTF-8
      csv += 'Mot Zarma,Signification Française,Exemple Zarma,Exemple Français,Catégorie,Prononciation,Niveau,Étymologie,Synonymes,Antonymes,Mots Liés\n';
      
      words.forEach(word => {
        const escapeCsvField = (field) => {
          if (!field) return '';
          const str = String(field).replace(/"/g, '""');
          // Entourer de guillemets si contient virgule, guillemet ou saut de ligne
          if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str}"`;
          }
          return str;
        };
        
        const row = [
          escapeCsvField(word.zarmaWord),
          escapeCsvField(word.frenchMeaning),
          escapeCsvField(word.zarmaExample),
          escapeCsvField(word.frenchExample),
          escapeCsvField(word.category),
          escapeCsvField(word.pronunciation),
          word.difficultyLevel || 1,
          escapeCsvField(word.etymology),
          escapeCsvField(word.synonyms),
          escapeCsvField(word.antonyms),
          escapeCsvField(word.relatedWords)
        ].join(',');
        
        csv += row + '\n';
      });

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="dictionnaire_zarma.csv"');
      res.send(csv);
    } else {
      // Export JSON (par défaut)
      const exportData = {
        exportDate: new Date().toISOString(),
        totalWords: words.length,
        version: '1.0',
        words: words
      };
      
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="dictionnaire_zarma.json"');
      res.json(exportData);
    }
  } catch (error) {
    console.error('Erreur lors de l\'export:', error);
    res.status(500).json({ error: 'Erreur lors de l\'export des données: ' + error.message });
  }
});


// POST /api/import - Import des données (CORRIGÉ)
// POST /api/import - Import des données (MODIFIÉ pour accepter les doublons)
app.post('/api/import', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Aucun fichier fourni' });
  }

  const filePath = req.file.path;
  const fileExtension = path.extname(req.file.originalname).toLowerCase();

  try {
    let wordsToImport = [];

    if (fileExtension === '.json') {
      // Import JSON
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(fileContent);
      
      if (data.words && Array.isArray(data.words)) {
        wordsToImport = data.words;
      } else if (Array.isArray(data)) {
        wordsToImport = data;
      } else {
        throw new Error('Format JSON invalide. Le fichier doit contenir un tableau de mots.');
      }
    } else if (fileExtension === '.csv') {
      // Import CSV amélioré
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const lines = fileContent.replace(/^\uFEFF/, '').split('\n'); // Retirer BOM UTF-8
      
      if (lines.length < 2) {
        throw new Error('Le fichier CSV doit contenir au moins une ligne d\'en-tête et une ligne de données');
      }
      
      // Parser CSV manuel pour gérer les champs entre guillemets
      const parseCsvLine = (line) => {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
          const char = line[i];
          
          if (char === '"') {
            if (inQuotes && line[i + 1] === '"') {
              // Double quote = quote échappée
              current += '"';
              i++; // Skip next quote
            } else {
              // Toggle quote mode
              inQuotes = !inQuotes;
            }
          } else if (char === ',' && !inQuotes) {
            // End of field
            result.push(current.trim());
            current = '';
          } else {
            current += char;
          }
        }
        
        // Add last field
        result.push(current.trim());
        return result;
      };
      
      const headers = parseCsvLine(lines[0]);
      console.log('En-têtes CSV détectés:', headers);
      
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line) {
          const values = parseCsvLine(line);
          
          if (values.length >= 4 && values[0] && values[1] && values[2] && values[3]) {
            const word = {
              zarmaWord: values[0] || '',
              frenchMeaning: values[1] || '',
              zarmaExample: values[2] || '',
              frenchExample: values[3] || '',
              category: values[4] || null,
              pronunciation: values[5] || null,
              difficultyLevel: parseInt(values[6]) || 1,
              etymology: values[7] || null,
              synonyms: values[8] ? values[8].split(';').map(s => s.trim()).filter(s => s) : [],
              antonyms: values[9] ? values[9].split(';').map(s => s.trim()).filter(s => s) : [],
              relatedWords: values[10] ? values[10].split(';').map(s => s.trim()).filter(s => s) : []
            };
            
            wordsToImport.push(word);
          }
        }
      }
    } else {
      throw new Error('Format de fichier non supporté. Utilisez .json ou .csv');
    }

    console.log(`Tentative d'import de ${wordsToImport.length} mots (avec doublons autorisés)`);

    let importedCount = 0;
    let errorCount = 0;
    const errors = [];

    // Import des mots avec transaction - TOUJOURS CRÉER DE NOUVEAUX ENREGISTREMENTS
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      for (let i = 0; i < wordsToImport.length; i++) {
        const word = wordsToImport[i];
        
        try {
          // Validation des champs requis
          if (!word.zarmaWord || !word.frenchMeaning || !word.zarmaExample || !word.frenchExample) {
            errors.push(`Ligne ${i + 1}: Champs requis manquants (zarmaWord, frenchMeaning, zarmaExample, frenchExample)`);
            errorCount++;
            continue;
          }

          // TOUJOURS créer un nouveau mot (pas de vérification d'existence)
          const result = await client.query(`
            INSERT INTO words (
              zarma_word, zarma_example, french_meaning, french_example,
              category, pronunciation, difficulty_level, etymology,
              synonyms, antonyms, related_words
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
          `, [
            word.zarmaWord,
            word.zarmaExample,
            word.frenchMeaning,
            word.frenchExample,
            word.category,
            word.pronunciation,
            word.difficultyLevel || 1,
            word.etymology,
            joinCommaSeparated(word.synonyms),
            joinCommaSeparated(word.antonyms),
            joinCommaSeparated(word.relatedWords)
          ]);
          
          // Initialiser les progrès d'apprentissage pour le nouveau mot
          await client.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [result.rows[0].id]);
          
          importedCount++;
          
        } catch (wordError) {
          console.error(`Erreur lors de l'import du mot "${word.zarmaWord}":`, wordError);
          errors.push(`Mot "${word.zarmaWord}" (ligne ${i + 1}): ${wordError.message}`);
          errorCount++;
        }
      }
      
      await client.query('COMMIT');
      console.log(`Import terminé: ${importedCount} mots créés, ${errorCount} erreurs`);
      
    } catch (transactionError) {
      await client.query('ROLLBACK');
      throw transactionError;
    } finally {
      client.release();
    }

    // Nettoyer le fichier temporaire
    try {
      fs.unlinkSync(filePath);
    } catch (cleanupError) {
      console.error('Erreur lors du nettoyage du fichier:', cleanupError);
    }

    res.json({
      success: true,
      message: `Import terminé: ${importedCount} mots créés (doublons autorisés), ${errorCount} erreurs`,
      imported: importedCount,
      updated: 0, // Plus de mise à jour, seulement des créations
      errors: errorCount,
      errorDetails: errors.length > 0 ? errors.slice(0, 10) : [], // Limiter à 10 erreurs pour la réponse
      duplicatesAllowed: true
    });
    
  } catch (error) {
    console.error('Erreur lors de l\'import:', error);
    
    // Nettoyer le fichier temporaire en cas d'erreur
    try {
      fs.unlinkSync(filePath);
    } catch (cleanupError) {
      console.error('Erreur lors du nettoyage du fichier:', cleanupError);
    }
    
    res.status(500).json({ 
      error: 'Erreur lors de l\'import: ' + error.message,
      success: false
    });
  }
});

// Dans votre server.js ou app.js
app.get('/health', async (req, res) => {
  try {
    // Vérifier la connexion à la base de données
    const db = require('./db');
    const dbHealthy = await db.healthCheck();
    
    res.status(200).json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      database: dbHealthy ? 'connected' : 'disconnected',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// POST /api/sync - Point de synchronisation pour l'application mobile
app.post('/api/sync', async (req, res) => {
  const { lastSync, deviceId } = req.body;
  
  let query = `
    SELECT w.*, 
           COALESCE(lp.view_count, 0) as view_count, 
           COALESCE(lp.practice_count, 0) as practice_count, 
           COALESCE(lp.is_learned, false) as is_learned,
           (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) > 0 as is_favorite
    FROM words w 
    LEFT JOIN learning_progress lp ON w.id = lp.word_id
  `;
  
  const params = [];
  
  if (lastSync) {
    query += ` WHERE w.updated_at > $1`;
    params.push(lastSync);
  }
  
  query += ` ORDER BY w.updated_at DESC`;
  
  try {
    const result = await pool.query(query, params);
    
    const words = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
    
    res.json({
      words,
      syncTime: Math.floor(Date.now() / 1000),
      total: words.length
    });
  } catch (error) {
    console.error('Erreur de synchronisation:', error);
    res.status(500).json({ error: 'Erreur de synchronisation' });
  }
});

// Routes pour les favoris
app.post('/api/favorites/:wordId', async (req, res) => {
  const { wordId } = req.params;
  
  try {
    // Vérifier si le mot existe
    const wordExists = await pool.query('SELECT id FROM words WHERE id = $1', [wordId]);
    if (wordExists.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }

    // Vérifier si déjà en favoris
    const existingFavorite = await pool.query('SELECT id FROM favorites WHERE word_id = $1', [wordId]);
    
    if (existingFavorite.rows.length === 0) {
      await pool.query('INSERT INTO favorites (word_id) VALUES ($1)', [wordId]);
      res.json({ success: true, message: 'Mot ajouté aux favoris' });
    } else {
      res.json({ success: true, message: 'Mot déjà en favoris' });
    }
  } catch (error) {
    console.error('Erreur lors de l\'ajout aux favoris:', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout aux favoris' });
  }
});

app.delete('/api/favorites/:wordId', async (req, res) => {
  const { wordId } = req.params;
  
  try {
    await pool.query('DELETE FROM favorites WHERE word_id = $1', [wordId]);
    res.json({ success: true, message: 'Mot retiré des favoris' });
  } catch (error) {
    console.error('Erreur lors de la suppression des favoris:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression des favoris' });
  }
});

app.get('/api/favorites', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT w.*, f.created_at as favorited_at
      FROM words w
      INNER JOIN favorites f ON w.id = f.word_id
      ORDER BY f.created_at DESC
    `);
    
    const favorites = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      favoritedAt: row.favorited_at
    }));
    
    res.json({ favorites });
  } catch (error) {
    console.error('Erreur lors de la récupération des favoris:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des favoris' });
  }
});

// Routes pour les progrès d'apprentissage
app.post('/api/learning-progress/:wordId', async (req, res) => {
  const { wordId } = req.params;
  const { action, isCorrect } = req.body; // action: 'view', 'practice'
  
  try {
    // Vérifier si le mot existe
    const wordExists = await pool.query('SELECT id FROM words WHERE id = $1', [wordId]);
    if (wordExists.rows.length === 0) {
      return res.status(404).json({ error: 'Mot non trouvé' });
    }

    // Vérifier si un progrès existe déjà
    const existingProgress = await pool.query('SELECT * FROM learning_progress WHERE word_id = $1', [wordId]);
    
    if (existingProgress.rows.length === 0) {
      // Créer un nouvel enregistrement de progrès
      await pool.query('INSERT INTO learning_progress (word_id) VALUES ($1)', [wordId]);
    }

    // Mettre à jour selon l'action
    if (action === 'view') {
      await pool.query(`
        UPDATE learning_progress 
        SET view_count = view_count + 1, updated_at = EXTRACT(EPOCH FROM NOW())
        WHERE word_id = $1
      `, [wordId]);
    } else if (action === 'practice') {
      let updateQuery = `
        UPDATE learning_progress 
        SET practice_count = practice_count + 1, 
            last_practiced = EXTRACT(EPOCH FROM NOW()),
            updated_at = EXTRACT(EPOCH FROM NOW())
      `;
      
      if (isCorrect !== undefined) {
        if (isCorrect) {
          updateQuery += `, correct_answers = correct_answers + 1`;
        } else {
          updateQuery += `, wrong_answers = wrong_answers + 1`;
        }
      }
      
      updateQuery += ` WHERE word_id = $1`;
      await pool.query(updateQuery, [wordId]);
    }

    res.json({ success: true, message: 'Progrès mis à jour' });
  } catch (error) {
    console.error('Erreur lors de la mise à jour des progrès:', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour des progrès' });
  }
});

// Routes pour les catégories
app.get('/api/categories', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT category, COUNT(*) as word_count
      FROM words 
      WHERE category IS NOT NULL AND category != ''
      GROUP BY category
      ORDER BY word_count DESC, category ASC
    `);
    
    const categories = result.rows.map(row => ({
      name: row.category,
      wordCount: parseInt(row.count)
    }));
    
    res.json({ categories });
  } catch (error) {
    console.error('Erreur lors de la récupération des catégories:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des catégories' });
  }
});

// Route pour la recherche avancée
app.post('/api/search', async (req, res) => {
  const { 
    query, 
    searchIn, // ['zarma', 'french', 'examples']
    categories, 
    difficulty, 
    limit = 50, 
    offset = 0 
  } = req.body;
  
  if (!query || query.trim().length < 2) {
    return res.status(400).json({ error: 'La requête de recherche doit contenir au moins 2 caractères' });
  }

  try {
    let sqlQuery = `
      SELECT w.*, 
             COALESCE(lp.view_count, 0) as view_count, 
             COALESCE(lp.practice_count, 0) as practice_count, 
             COALESCE(lp.is_learned, false) as is_learned,
             (SELECT COUNT(*) FROM favorites f WHERE f.word_id = w.id) > 0 as is_favorite
      FROM words w 
      LEFT JOIN learning_progress lp ON w.id = lp.word_id
      WHERE 1=1
    `;
    
    const params = [];
    let paramCount = 0;
    
    // Construire la condition de recherche
    const searchConditions = [];
    const searchTerm = `%${query.trim()}%`;
    
    if (!searchIn || searchIn.includes('zarma')) {
      paramCount++;
      searchConditions.push(`w.zarma_word ILIKE ${paramCount}`);
      params.push(searchTerm);
    }
    
    if (!searchIn || searchIn.includes('french')) {
      paramCount++;
      searchConditions.push(`w.french_meaning ILIKE ${paramCount}`);
      params.push(searchTerm);
    }
    
    if (!searchIn || searchIn.includes('examples')) {
      paramCount++;
      searchConditions.push(`w.zarma_example ILIKE ${paramCount}`);
      params.push(searchTerm);
      
      paramCount++;
      searchConditions.push(`w.french_example ILIKE ${paramCount}`);
      params.push(searchTerm);
    }
    
    if (searchConditions.length > 0) {
      sqlQuery += ` AND (${searchConditions.join(' OR ')})`;
    }
    
    // Filtres additionnels
    if (categories && categories.length > 0) {
      paramCount++;
      sqlQuery += ` AND w.category = ANY(${paramCount})`;
      params.push(categories);
    }
    
    if (difficulty && difficulty.length > 0) {
      paramCount++;
      sqlQuery += ` AND w.difficulty_level = ANY(${paramCount})`;
      params.push(difficulty);
    }
    
    sqlQuery += ` ORDER BY w.usage_frequency DESC, w.zarma_word ASC`;
    
    // Pagination
    paramCount++;
    sqlQuery += ` LIMIT ${paramCount}`;
    params.push(parseInt(limit));
    
    paramCount++;
    sqlQuery += ` OFFSET ${paramCount}`;
    params.push(parseInt(offset));
    
    const result = await pool.query(sqlQuery, params);
    
    const words = result.rows.map(row => ({
      id: row.id,
      zarmaWord: row.zarma_word,
      zarmaExample: row.zarma_example,
      frenchMeaning: row.french_meaning,
      frenchExample: row.french_example,
      category: row.category,
      pronunciation: row.pronunciation,
      difficultyLevel: row.difficulty_level,
      etymology: row.etymology,
      synonyms: parseCommaSeparated(row.synonyms),
      antonyms: parseCommaSeparated(row.antonyms),
      relatedWords: parseCommaSeparated(row.related_words),
      usageFrequency: row.usage_frequency,
      audioPath: row.audio_path,
      imagePath: row.image_path,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      viewCount: row.view_count,
      practiceCount: row.practice_count,
      isLearned: row.is_learned,
      isFavorite: row.is_favorite
    }));
    
    res.json({ 
      words, 
      total: words.length,
      hasMore: words.length === parseInt(limit)
    });
  } catch (error) {
    console.error('Erreur lors de la recherche:', error);
    res.status(500).json({ error: 'Erreur lors de la recherche' });
  }
});

// Fonction pour nettoyer les anciennes sessions expirées
async function cleanupExpiredSessions() {
  try {
    const result = await pool.query('DELETE FROM admin_sessions WHERE expires_at < $1', [Math.floor(Date.now() / 1000)]);
    if (result.rowCount > 0) {
      console.log(`Nettoyage: ${result.rowCount} sessions expirées supprimées`);
    }
  } catch (error) {
    console.error('Erreur lors du nettoyage des sessions:', error);
  }
}

// Initialisation de la base de données PostgreSQL
async function initializeDatabase() {
  try {
    // Test de connexion à la base de données
    await pool.query('SELECT NOW()');
    console.log('✅ Connexion à PostgreSQL établie avec succès');

    // Créer les tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users(
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email VARCHAR(255),
        role VARCHAR(50) DEFAULT 'admin',
        is_active BOOLEAN DEFAULT TRUE,
        last_login BIGINT,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        ip_address INET,
        user_agent TEXT,
        expires_at BIGINT NOT NULL,
        is_remember_me BOOLEAN DEFAULT FALSE,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_attempts(
        id SERIAL PRIMARY KEY,
        ip_address INET NOT NULL,
        username VARCHAR(255),
        success BOOLEAN NOT NULL,
        attempt_time BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        user_agent TEXT
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS words(
        id SERIAL PRIMARY KEY,
        zarma_word VARCHAR(255) NOT NULL,
        zarma_example TEXT NOT NULL,
        french_meaning TEXT NOT NULL,
        french_example TEXT NOT NULL,
        category VARCHAR(100),
        pronunciation VARCHAR(255),
        difficulty_level INTEGER DEFAULT 1,
        etymology TEXT,
        synonyms TEXT,
        antonyms TEXT,
        related_words TEXT,
        usage_frequency INTEGER DEFAULT 0,
        audio_path VARCHAR(255),
        image_path VARCHAR(255),
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL REFERENCES words(id) ON DELETE CASCADE,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        UNIQUE(word_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_progress(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL REFERENCES words(id) ON DELETE CASCADE,
        view_count INTEGER DEFAULT 0,
        practice_count INTEGER DEFAULT 0,
        correct_answers INTEGER DEFAULT 0,
        wrong_answers INTEGER DEFAULT 0,
        is_learned BOOLEAN DEFAULT FALSE,
        last_practiced BIGINT,
        learning_streak INTEGER DEFAULT 0,
        difficulty_adjustment REAL DEFAULT 1.0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        UNIQUE(word_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_notes(
        id SERIAL PRIMARY KEY,
        word_id INTEGER NOT NULL REFERENCES words(id) ON DELETE CASCADE,
        note_text TEXT NOT NULL,
        tags TEXT,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS usage_stats(
        id SERIAL PRIMARY KEY,
        date DATE NOT NULL,
        words_studied INTEGER DEFAULT 0,
        time_spent INTEGER DEFAULT 0,
        quiz_completed INTEGER DEFAULT 0,
        new_words_learned INTEGER DEFAULT 0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
        UNIQUE(date)
      )
    `);
    await pool.query(`
  CREATE TABLE IF NOT EXISTS quizzes(
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    quiz_type VARCHAR(100),
    difficulty VARCHAR(50),
    time_limit INTEGER DEFAULT 30,
    primary_color VARCHAR(7),
    is_active BOOLEAN DEFAULT TRUE,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS quiz_questions(
    id SERIAL PRIMARY KEY,
    quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
    question_text TEXT NOT NULL,
    explanation TEXT,
    audio_path VARCHAR(255),
    question_order INTEGER DEFAULT 0,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS question_options(
    id SERIAL PRIMARY KEY,
    question_id INTEGER NOT NULL REFERENCES quiz_questions(id) ON DELETE CASCADE,
    option_text TEXT NOT NULL,
    is_correct BOOLEAN DEFAULT FALSE,
    option_order INTEGER DEFAULT 0,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )
`);

// Tables pour les exercices
await pool.query(`
  CREATE TABLE IF NOT EXISTS exercises(
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    exercise_type VARCHAR(100),
    primary_color VARCHAR(7),
    is_active BOOLEAN DEFAULT TRUE,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS exercise_items(
    id SERIAL PRIMARY KEY,
    exercise_id INTEGER NOT NULL REFERENCES exercises(id) ON DELETE CASCADE,
    zarma_text TEXT NOT NULL,
    french_text TEXT NOT NULL,
    tip TEXT,
    audio_path VARCHAR(255),
    item_order INTEGER DEFAULT 0,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
  )
`);
// Tables pour les notifications
await pool.query(`
  CREATE TABLE IF NOT EXISTS notifications(
    id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(50) DEFAULT 'info',
    priority VARCHAR(50) DEFAULT 'normal',
    target VARCHAR(50) DEFAULT 'all',
    created_by VARCHAR(255),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
  )
`);
await pool.query(`
  CREATE TABLE IF NOT EXISTS user_devices(
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES admin_users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    fcm_token TEXT NOT NULL,
    platform VARCHAR(50),
    app_version VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(device_id, fcm_token)
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS notification_reads(
    id SERIAL PRIMARY KEY,
    notification_id VARCHAR(255) NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    read_at BIGINT NOT NULL,
    UNIQUE(notification_id, device_id)
  )
`);

await pool.query('CREATE INDEX IF NOT EXISTS idx_notifications_expires ON notifications(expires_at)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_notification_reads_device ON notification_reads(device_id)');

// Créer les index pour les nouvelles tables
await pool.query('CREATE INDEX IF NOT EXISTS idx_quizzes_category ON quizzes(category)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_quizzes_type ON quizzes(quiz_type)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_quiz_questions_quiz ON quiz_questions(quiz_id)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_question_options_question ON question_options(question_id)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_exercises_type ON exercises(exercise_type)');
await pool.query('CREATE INDEX IF NOT EXISTS idx_exercise_items_exercise ON exercise_items(exercise_id)');


    // Créer les index
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_zarma ON words(zarma_word)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_french ON words(french_meaning)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_category ON words(category)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_words_difficulty ON words(difficulty_level)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token_hash)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_learning_progress_word ON learning_progress(word_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_favorites_word ON favorites(word_id)');

    console.log('✅ Base de données PostgreSQL initialisée avec succès');
    
    // Créer un utilisateur admin par défaut
    await createDefaultAdmin();

  } catch (error) {
    console.error('❌ Erreur lors de l\'initialisation de la base de données:', error);
    // Ne pas quitter le processus en production pour permettre les redémarrages
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
}

// Création de l'administrateur par défaut
async function createDefaultAdmin() {
  const defaultUsername = 'admin';
  const defaultPassword = 'admin123';

  try {
    const userCheck = await pool.query('SELECT id FROM admin_users WHERE username = $1', [defaultUsername]);
    
    if (userCheck.rows.length === 0) {
      const passwordHash = await bcrypt.hash(defaultPassword, 12);
      
      await pool.query(
        'INSERT INTO admin_users (username, password_hash, email, role) VALUES ($1, $2, $3, $4)',
        [defaultUsername, passwordHash, 'admin@dictionnaire-zarma.com', 'super_admin']
      );
      
      console.log('👤 Administrateur par défaut créé:');
      console.log('   Utilisateur: admin');
      console.log('   Mot de passe: admin123');
      console.log('   ⚠️  CHANGEZ CES IDENTIFIANTS EN PRODUCTION !');
    }
  } catch (error) {
    console.error('Erreur lors de la création de l\'admin:', error);
  }
}

// Gestion des erreurs non capturées
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Graceful shutdown
  process.exit(1);
});

// Gestion propre de l'arrêt du serveur
process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur...');
  try {
    await pool.end();
    console.log('✅ Connexions PostgreSQL fermées proprement');
  } catch (error) {
    console.error('Erreur lors de la fermeture des connexions:', error);
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🛑 Signal SIGTERM reçu, arrêt propre...');
  try {
    await pool.end();
    console.log('✅ Connexions PostgreSQL fermées proprement');
  } catch (error) {
    console.error('Erreur lors de la fermeture des connexions:', error);
  }
  process.exit(0);
});

// Nettoyer les sessions expirées toutes les heures
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// Démarrage du serveur
async function startServer() {
  try {
    // Initialiser la base de données
    await initializeDatabase();
    
    // Démarrer le serveur
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur API Dictionnaire Zarma (PostgreSQL) démarré sur le port ${PORT}`);
      console.log(`🔗 API disponible sur: http://localhost:${PORT}/api`);
      console.log(`🔐 Authentification requise pour les routes d'administration`);
      console.log(`💾 Base de données: PostgreSQL`);
      console.log(`🌍 Environnement: ${process.env.NODE_ENV || 'production'}`);
    });

    // Gestion de l'arrêt propre du serveur
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} reçu, arrêt propre du serveur...`);
      server.close(async () => {
        console.log('📴 Serveur HTTP fermé');
        try {
          await pool.end();
          console.log('✅ Connexions PostgreSQL fermées proprement');
        } catch (error) {
          console.error('Erreur lors de la fermeture des connexions:', error);
        }
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error);
    // Ne pas quitter le processus en production
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
}

// Démarrer le serveur
startServer();

module.exports = app;
