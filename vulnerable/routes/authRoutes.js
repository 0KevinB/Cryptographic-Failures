// VERSIÓN VULNERABLE - Rutas de Autenticación
const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');

// ❌ PROBLEMA: Sin rate limiting - vulnerable a ataques de fuerza bruta
router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.get('/profile', AuthController.getProfile);
router.get('/users', AuthController.listUsers);
router.post('/logout', AuthController.logout);

module.exports = router;
