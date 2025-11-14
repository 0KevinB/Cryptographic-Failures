// VERSIÓN SEGURA - Modelo de Usuario
const { db, encryptionHelper } = require('../config/database');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const validator = require('validator');

class User {
    // ✓ SOLUCIÓN: Usar bcrypt con salt rounds apropiado
    static async hashPassword(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }

    // ✓ SOLUCIÓN: Validar complejidad de contraseña
    static validatePassword(password) {
        const errors = [];

        if (password.length < 12) {
            errors.push('Contraseña debe tener al menos 12 caracteres');
        }
        if (!/[A-Z]/.test(password)) {
            errors.push('Contraseña debe contener al menos una mayúscula');
        }
        if (!/[a-z]/.test(password)) {
            errors.push('Contraseña debe contener al menos una minúscula');
        }
        if (!/[0-9]/.test(password)) {
            errors.push('Contraseña debe contener al menos un número');
        }
        if (!/[!@#$%^&*]/.test(password)) {
            errors.push('Contraseña debe contener al menos un carácter especial (!@#$%^&*)');
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    // ✓ SOLUCIÓN: Validar y sanitizar entrada
    static validateUserData(userData) {
        const errors = [];

        if (!userData.username || userData.username.length < 3) {
            errors.push('Username debe tener al menos 3 caracteres');
        }

        if (!validator.isEmail(userData.email || '')) {
            errors.push('Email inválido');
        }

        if (userData.ssn && !/^\d{3}-\d{2}-\d{4}$/.test(userData.ssn)) {
            errors.push('SSN debe tener formato XXX-XX-XXXX');
        }

        if (userData.credit_card) {
            // Permitir tarjetas con o sin guiones/espacios
            const cardWithoutSpaces = userData.credit_card.replace(/[-\s]/g, '');
            // Validación básica: debe tener entre 13 y 19 dígitos
            if (!/^\d{13,19}$/.test(cardWithoutSpaces)) {
                errors.push('Número de tarjeta inválido (debe contener 13-19 dígitos)');
            }
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    // Crear usuario
    static async create(userData, callback) {
        try {
            const { username, password, email, ssn, credit_card, medical_info } = userData;

            // Validar datos
            const dataValidation = this.validateUserData(userData);
            if (!dataValidation.valid) {
                return callback(new Error(dataValidation.errors.join(', ')), null);
            }

            // Validar contraseña
            const passwordValidation = this.validatePassword(password);
            if (!passwordValidation.valid) {
                return callback(new Error(passwordValidation.errors.join(', ')), null);
            }

            // ✓ SOLUCIÓN: Hashear contraseña con bcrypt
            const hashedPassword = await this.hashPassword(password);

            // ✓ SOLUCIÓN: Cifrar datos sensibles antes de almacenar
            const ssnEncrypted = ssn ? encryptionHelper.encrypt(ssn) : null;
            const creditCardEncrypted = credit_card ? encryptionHelper.encrypt(credit_card) : null;
            const medicalInfoEncrypted = medical_info ? encryptionHelper.encrypt(medical_info) : null;

            const query = `
                INSERT INTO users (username, password_hash, email, ssn_encrypted, credit_card_encrypted, medical_info_encrypted)
                VALUES (?, ?, ?, ?, ?, ?)
            `;

            db.run(
                query,
                [username, hashedPassword, email, ssnEncrypted, creditCardEncrypted, medicalInfoEncrypted],
                function(err) {
                    if (err) {
                        return callback(err, null);
                    }

                    // Log de auditoría
                    User.logAudit(this.lastID, 'USER_CREATED', null, 'Usuario registrado exitosamente');

                    callback(null, {
                        id: this.lastID,
                        username,
                        email
                    });
                }
            );
        } catch (error) {
            callback(error, null);
        }
    }

    // Buscar usuario por username
    static findByUsername(username, callback) {
        const query = 'SELECT * FROM users WHERE username = ?';
        db.get(query, [username], (err, row) => {
            callback(err, row);
        });
    }

    // Buscar usuario por ID con descifrado de datos
    static findById(id, includeSensitive = false, callback) {
        const query = 'SELECT * FROM users WHERE id = ?';
        db.get(query, [id], (err, row) => {
            if (err || !row) {
                return callback(err, null);
            }

            // ✓ SOLUCIÓN: Solo descifrar si es necesario
            if (includeSensitive) {
                try {
                    row.ssn = row.ssn_encrypted ? encryptionHelper.decrypt(row.ssn_encrypted) : null;
                    row.credit_card = row.credit_card_encrypted ? encryptionHelper.decrypt(row.credit_card_encrypted) : null;
                    row.medical_info = row.medical_info_encrypted ? encryptionHelper.decrypt(row.medical_info_encrypted) : null;
                } catch (decryptError) {
                    console.error('Error al descifrar datos:', decryptError);
                }
            }

            // Remover datos cifrados y hash de la respuesta
            delete row.password_hash;
            delete row.ssn_encrypted;
            delete row.credit_card_encrypted;
            delete row.medical_info_encrypted;

            callback(null, row);
        });
    }

    // Verificar contraseña
    static async verifyPassword(plainPassword, hashedPassword) {
        return await bcrypt.compare(plainPassword, hashedPassword);
    }

    // ✓ SOLUCIÓN: Crear sesión segura con token aleatorio criptográficamente fuerte
    static createSession(userId, ipAddress, userAgent, callback) {
        // Token de 32 bytes (256 bits) en hexadecimal
        const sessionToken = crypto.randomBytes(32).toString('hex');

        // Expiración: 24 horas
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        const query = `
            INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        `;

        db.run(query, [userId, sessionToken, expiresAt, ipAddress, userAgent], function(err) {
            if (err) {
                return callback(err, null);
            }

            // Log de auditoría
            User.logAudit(userId, 'SESSION_CREATED', ipAddress, 'Usuario inició sesión');

            callback(null, sessionToken);
        });
    }

    // Verificar sesión
    static verifySession(sessionToken, callback) {
        const query = `
            SELECT u.*, s.expires_at
            FROM users u
            INNER JOIN sessions s ON u.id = s.user_id
            WHERE s.session_token = ?
        `;

        db.get(query, [sessionToken], (err, row) => {
            if (err || !row) {
                return callback(err || new Error('Sesión no encontrada'), null);
            }

            // ✓ SOLUCIÓN: Verificar expiración
            const now = new Date();
            const expiresAt = new Date(row.expires_at);

            if (now > expiresAt) {
                return callback(new Error('Sesión expirada'), null);
            }

            callback(null, row);
        });
    }

    // Invalidar sesión
    static deleteSession(sessionToken, callback) {
        const query = 'DELETE FROM sessions WHERE session_token = ?';
        db.run(query, [sessionToken], function(err) {
            callback(err);
        });
    }

    // ✓ SOLUCIÓN: Manejo de intentos fallidos de login
    static recordFailedLogin(userId, callback) {
        const query = `
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                account_locked_until = CASE
                    WHEN failed_login_attempts + 1 >= 5
                    THEN datetime('now', '+15 minutes')
                    ELSE account_locked_until
                END
            WHERE id = ?
        `;

        db.run(query, [userId], function(err) {
            callback(err);
        });
    }

    // Resetear intentos fallidos
    static resetFailedLogins(userId, callback) {
        const query = `
            UPDATE users
            SET failed_login_attempts = 0,
                account_locked_until = NULL,
                last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        `;

        db.run(query, [userId], function(err) {
            callback(err);
        });
    }

    // Verificar si cuenta está bloqueada
    static isAccountLocked(user) {
        if (!user.account_locked_until) {
            return false;
        }

        const now = new Date();
        const lockedUntil = new Date(user.account_locked_until);

        return now < lockedUntil;
    }

    // ✓ SOLUCIÓN: Logging de auditoría
    static logAudit(userId, action, ipAddress, details) {
        const query = `
            INSERT INTO audit_log (user_id, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        `;

        db.run(query, [userId, action, ipAddress, details], (err) => {
            if (err) {
                console.error('Error al guardar log de auditoría:', err);
            }
        });
    }

    // Limpiar sesiones expiradas (tarea de mantenimiento)
    static cleanExpiredSessions(callback) {
        const query = 'DELETE FROM sessions WHERE datetime(expires_at) < datetime("now")';
        db.run(query, [], function(err) {
            if (callback) callback(err, this.changes);
        });
    }
}

module.exports = User;
