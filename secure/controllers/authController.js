// VERSIÓN SEGURA - Controlador de Autenticación
const User = require('../models/User');
const validator = require('validator');

class AuthController {
    // Registro de usuario
    static async register(req, res) {
        try {
            const { username, password, email, ssn, credit_card, medical_info } = req.body;

            // ✓ SOLUCIÓN: Sanitizar entrada
            const sanitizedData = {
                username: validator.escape(username || ''),
                password,
                email: validator.normalizeEmail(email || ''),
                ssn: ssn ? ssn.trim() : null,
                credit_card: credit_card ? credit_card.trim() : null,
                medical_info: medical_info ? validator.escape(medical_info) : null
            };

            if (!sanitizedData.username || !password || !sanitizedData.email) {
                return res.status(400).json({
                    success: false,
                    message: 'Faltan campos requeridos'
                });
            }

            // Crear usuario (validación incluida en el modelo)
            User.create(sanitizedData, (err, user) => {
                if (err) {
                    console.error('Error al crear usuario:', err.message);
                    return res.status(400).json({
                        success: false,
                        message: err.message
                    });
                }

                res.status(201).json({
                    success: true,
                    message: 'Usuario creado exitosamente',
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email
                    }
                });
            });
        } catch (error) {
            console.error('Error en registro:', error);
            res.status(500).json({
                success: false,
                message: 'Error al procesar la solicitud'
            });
        }
    }

    // Login
    static async login(req, res) {
        try {
            const { username, password } = req.body;

            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Username y password requeridos'
                });
            }

            // Buscar usuario
            User.findByUsername(username, async (err, user) => {
                if (err) {
                    console.error('Error en login:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error al procesar la solicitud'
                    });
                }

                // ✓ SOLUCIÓN: Mensaje genérico para no revelar si el usuario existe
                if (!user) {
                    User.logAudit(null, 'LOGIN_FAILED', req.ip, `Intento de login con usuario inexistente: ${username}`);
                    return res.status(401).json({
                        success: false,
                        message: 'Credenciales inválidas'
                    });
                }

                // ✓ SOLUCIÓN: Verificar si la cuenta está bloqueada
                if (User.isAccountLocked(user)) {
                    User.logAudit(user.id, 'LOGIN_BLOCKED', req.ip, 'Intento de login con cuenta bloqueada');
                    return res.status(423).json({
                        success: false,
                        message: 'Cuenta temporalmente bloqueada por múltiples intentos fallidos. Intente más tarde.'
                    });
                }

                // Verificar contraseña
                const passwordMatch = await User.verifyPassword(password, user.password_hash);

                if (!passwordMatch) {
                    // Registrar intento fallido
                    User.recordFailedLogin(user.id, () => {});
                    User.logAudit(user.id, 'LOGIN_FAILED', req.ip, 'Contraseña incorrecta');

                    return res.status(401).json({
                        success: false,
                        message: 'Credenciales inválidas'
                    });
                }

                // ✓ SOLUCIÓN: Resetear intentos fallidos en login exitoso
                User.resetFailedLogins(user.id, () => {});

                // Obtener información del cliente
                const ipAddress = req.ip;
                const userAgent = req.get('User-Agent') || 'Unknown';

                // Crear sesión segura
                User.createSession(user.id, ipAddress, userAgent, (err, sessionToken) => {
                    if (err) {
                        console.error('Error al crear sesión:', err);
                        return res.status(500).json({
                            success: false,
                            message: 'Error al crear sesión'
                        });
                    }

                    // ✓ SOLUCIÓN: Cookie con todas las flags de seguridad
                    res.cookie('session_token', sessionToken, {
                        httpOnly: true,      // No accesible desde JavaScript
                        secure: process.env.NODE_ENV === 'production',  // Solo HTTPS en producción
                        sameSite: 'strict',  // Protección contra CSRF
                        maxAge: 24 * 60 * 60 * 1000  // 24 horas
                    });

                    res.json({
                        success: true,
                        message: 'Login exitoso',
                        user: {
                            id: user.id,
                            username: user.username,
                            email: user.email
                        }
                    });
                });
            });
        } catch (error) {
            console.error('Error en login:', error);
            res.status(500).json({
                success: false,
                message: 'Error al procesar la solicitud'
            });
        }
    }

    // Obtener perfil de usuario
    static getProfile(req, res) {
        const sessionToken = req.cookies.session_token || req.headers['x-session-token'];

        if (!sessionToken) {
            return res.status(401).json({
                success: false,
                message: 'No autenticado'
            });
        }

        User.verifySession(sessionToken, (err, user) => {
            if (err || !user) {
                return res.status(401).json({
                    success: false,
                    message: 'Sesión inválida o expirada'
                });
            }

            // ✓ SOLUCIÓN: Obtener datos con descifrado solo si el usuario tiene permiso
            User.findById(user.id, true, (err, userData) => {
                if (err) {
                    console.error('Error al obtener perfil:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error al obtener perfil'
                    });
                }

                // ✓ SOLUCIÓN: Enmascarar datos sensibles parcialmente
                const maskedData = {
                    id: userData.id,
                    username: userData.username,
                    email: userData.email,
                    ssn: userData.ssn ? '***-**-' + userData.ssn.slice(-4) : null,
                    credit_card: userData.credit_card ? '**** **** **** ' + userData.credit_card.slice(-4) : null,
                    medical_info: userData.medical_info ? '[Información médica disponible]' : null,
                    created_at: userData.created_at,
                    last_login: userData.last_login
                };

                User.logAudit(user.id, 'PROFILE_VIEWED', req.ip, 'Usuario consultó su perfil');

                res.json({
                    success: true,
                    user: maskedData
                });
            });
        });
    }

    // Obtener datos sensibles completos (requiere reautenticación)
    static getSensitiveData(req, res) {
        const sessionToken = req.cookies.session_token || req.headers['x-session-token'];
        const { password } = req.body;

        if (!sessionToken || !password) {
            return res.status(400).json({
                success: false,
                message: 'Sesión y contraseña requeridas'
            });
        }

        User.verifySession(sessionToken, async (err, sessionUser) => {
            if (err || !sessionUser) {
                return res.status(401).json({
                    success: false,
                    message: 'Sesión inválida'
                });
            }

            // ✓ SOLUCIÓN: Requerir contraseña para acceder a datos sensibles
            const passwordMatch = await User.verifyPassword(password, sessionUser.password_hash);

            if (!passwordMatch) {
                User.logAudit(sessionUser.id, 'SENSITIVE_DATA_ACCESS_DENIED', req.ip, 'Contraseña incorrecta al solicitar datos sensibles');
                return res.status(401).json({
                    success: false,
                    message: 'Contraseña incorrecta'
                });
            }

            User.findById(sessionUser.id, true, (err, userData) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        message: 'Error al obtener datos'
                    });
                }

                User.logAudit(sessionUser.id, 'SENSITIVE_DATA_ACCESSED', req.ip, 'Usuario accedió a datos sensibles completos');

                res.json({
                    success: true,
                    sensitiveData: {
                        ssn: userData.ssn,
                        credit_card: userData.credit_card,
                        medical_info: userData.medical_info
                    }
                });
            });
        });
    }

    // ✓ SOLUCIÓN: Listar usuarios sin exponer datos sensibles
    static listUsers(req, res) {
        const sessionToken = req.cookies.session_token || req.headers['x-session-token'];

        if (!sessionToken) {
            return res.status(401).json({
                success: false,
                message: 'No autenticado'
            });
        }

        User.verifySession(sessionToken, (err, user) => {
            if (err || !user) {
                return res.status(401).json({
                    success: false,
                    message: 'Sesión inválida'
                });
            }

            const { db } = require('../config/database');

            // Solo obtener información pública
            db.all('SELECT id, username, email, created_at FROM users', [], (err, rows) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        message: 'Error al obtener usuarios'
                    });
                }

                User.logAudit(user.id, 'USERS_LIST_VIEWED', req.ip, 'Usuario consultó lista de usuarios');

                res.json({
                    success: true,
                    users: rows
                });
            });
        });
    }

    // Logout
    static logout(req, res) {
        const sessionToken = req.cookies.session_token || req.headers['x-session-token'];

        if (sessionToken) {
            User.deleteSession(sessionToken, (err) => {
                if (err) {
                    console.error('Error al eliminar sesión:', err);
                }
            });
        }

        res.clearCookie('session_token');
        res.json({
            success: true,
            message: 'Logout exitoso'
        });
    }
}

module.exports = AuthController;
