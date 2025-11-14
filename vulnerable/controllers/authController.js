// VERSIÓN VULNERABLE - Controlador de Autenticación
const User = require('../models/User');

class AuthController {
    // Registro de usuario
    static register(req, res) {
        const { username, password, email, ssn, credit_card, medical_info } = req.body;

        // ❌ PROBLEMA: Sin validación de contraseña fuerte
        if (!username || !password || !email) {
            return res.status(400).json({
                success: false,
                message: 'Faltan campos requeridos'
            });
        }

        User.create({ username, password, email, ssn, credit_card, medical_info }, (err, user) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Error al crear usuario',
                    error: err.message
                });
            }

            res.status(201).json({
                success: true,
                message: 'Usuario creado exitosamente',
                user
            });
        });
    }

    // Login
    static login(req, res) {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username y password requeridos'
            });
        }

        User.findByUsername(username, (err, user) => {
            if (err || !user) {
                return res.status(401).json({
                    success: false,
                    message: 'Credenciales inválidas'
                });
            }

            // Verificar contraseña
            if (!User.verifyPassword(password, user.password)) {
                return res.status(401).json({
                    success: false,
                    message: 'Credenciales inválidas'
                });
            }

            // Crear sesión
            User.createSession(user.id, (err, sessionToken) => {
                if (err) {
                    return res.status(500).json({
                        success: false,
                        message: 'Error al crear sesión'
                    });
                }

                // ❌ PROBLEMA: Cookie sin flags de seguridad
                console.log('⚠️  VULNERABILIDAD: Cookie sin HTTPOnly, Secure, SameSite');
                res.cookie('session_token', sessionToken);

                res.json({
                    success: true,
                    message: 'Login exitoso',
                    sessionToken,
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email
                    }
                });
            });
        });
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
                    message: 'Sesión inválida'
                });
            }

            // ❌ PROBLEMA: Exponer TODOS los datos sensibles
            console.log('⚠️  VULNERABILIDAD: Exponiendo datos sensibles en la respuesta');
            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    ssn: user.ssn,                    // ❌ Expuesto
                    credit_card: user.credit_card,    // ❌ Expuesto
                    medical_info: user.medical_info   // ❌ Expuesto
                }
            });
        });
    }

    // Listar todos los usuarios
    static listUsers(req, res) {
        User.getAll((err, users) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Error al obtener usuarios'
                });
            }

            // ❌ PROBLEMA: Exponer información sensible de todos los usuarios
            console.log('⚠️  VULNERABILIDAD: Exponiendo datos de TODOS los usuarios sin restricción');
            res.json({
                success: true,
                users: users.map(u => ({
                    id: u.id,
                    username: u.username,
                    email: u.email,
                    password: u.password,             // ❌ Hash MD5 expuesto
                    ssn: u.ssn,                       // ❌ Expuesto
                    credit_card: u.credit_card,       // ❌ Expuesto
                    medical_info: u.medical_info      // ❌ Expuesto
                }))
            });
        });
    }

    // Logout
    static logout(req, res) {
        res.clearCookie('session_token');
        res.json({
            success: true,
            message: 'Logout exitoso'
        });
    }
}

module.exports = AuthController;
