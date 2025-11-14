// VERSIÓN VULNERABLE - Modelo de Usuario
const db = require('../config/database');
const crypto = require('crypto');

class User {
    // ❌ PROBLEMA 1: Usar MD5 para hashear contraseñas
    static hashPassword(password) {
        console.log('⚠️  VULNERABILIDAD: Usando MD5 para contraseñas');
        return crypto.createHash('md5').update(password).digest('hex');
    }

    // Crear usuario
    static create(userData, callback) {
        const { username, password, email, ssn, credit_card, medical_info } = userData;

        // ❌ PROBLEMA 2: Almacenar datos sensibles en texto plano
        console.log('⚠️  VULNERABILIDAD: Almacenando datos sensibles SIN cifrar');

        const hashedPassword = this.hashPassword(password);

        const query = `
            INSERT INTO users (username, password, email, ssn, credit_card, medical_info)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        db.run(query, [username, hashedPassword, email, ssn, credit_card, medical_info], function(err) {
            if (err) {
                return callback(err, null);
            }
            callback(null, { id: this.lastID, username, email });
        });
    }

    // Buscar usuario por username
    static findByUsername(username, callback) {
        const query = 'SELECT * FROM users WHERE username = ?';
        db.get(query, [username], (err, row) => {
            callback(err, row);
        });
    }

    // Buscar usuario por ID
    static findById(id, callback) {
        const query = 'SELECT * FROM users WHERE id = ?';
        db.get(query, [id], (err, row) => {
            callback(err, row);
        });
    }

    // Obtener todos los usuarios
    static getAll(callback) {
        const query = 'SELECT * FROM users';
        db.all(query, [], (err, rows) => {
            callback(err, rows);
        });
    }

    // Verificar contraseña
    static verifyPassword(plainPassword, hashedPassword) {
        const hash = this.hashPassword(plainPassword);
        return hash === hashedPassword;
    }

    // ❌ PROBLEMA 3: Crear sesiones con tokens predecibles
    static createSession(userId, callback) {
        console.log('⚠️  VULNERABILIDAD: Token de sesión predecible');
        // Token débil basado en timestamp
        const sessionToken = crypto.createHash('md5')
            .update(userId.toString() + Date.now().toString())
            .digest('hex');

        const query = 'INSERT INTO sessions (user_id, session_token) VALUES (?, ?)';
        db.run(query, [userId, sessionToken], function(err) {
            callback(err, sessionToken);
        });
    }

    // Verificar sesión
    static verifySession(sessionToken, callback) {
        const query = `
            SELECT u.* FROM users u
            INNER JOIN sessions s ON u.id = s.user_id
            WHERE s.session_token = ?
        `;
        db.get(query, [sessionToken], (err, row) => {
            callback(err, row);
        });
    }
}

module.exports = User;
