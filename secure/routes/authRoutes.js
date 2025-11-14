// VERSIÓN SEGURA - Rutas de Autenticación
const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const rateLimit = require('express-rate-limit');

// ✓ SOLUCIÓN: Rate limiting para prevenir ataques de fuerza bruta
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos por ventana
    message: {
        success: false,
        message: 'Demasiados intentos de login. Por favor intente más tarde.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 3, // máximo 3 registros por hora por IP
    message: {
        success: false,
        message: 'Demasiados intentos de registro. Por favor intente más tarde.'
    }
});

const sensitiveDataLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    message: {
        success: false,
        message: 'Demasiadas solicitudes de datos sensibles.'
    }
});

// Rutas públicas con rate limiting
router.post('/register', registerLimiter, AuthController.register);
router.post('/login', loginLimiter, AuthController.login);

// Rutas protegidas
router.get('/profile', AuthController.getProfile);
router.post('/sensitive-data', sensitiveDataLimiter, AuthController.getSensitiveData);
router.get('/users', AuthController.listUsers);
router.post('/logout', AuthController.logout);

module.exports = router;
