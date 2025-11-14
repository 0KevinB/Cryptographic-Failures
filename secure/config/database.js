// VERSIÓN SEGURA - Base de Datos con Cifrado
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const dbPath = path.join(__dirname, '..', 'database', 'secure.db');

// Validar que existe la clave de cifrado
if (!process.env.ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY no está configurada en .env');
}

// Crear conexión a la base de datos
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
    } else {
        console.log('✓ Conectado a base de datos SEGURA (con cifrado)');
    }
});

// Funciones de cifrado/descifrado para datos en reposo
class EncryptionHelper {
    constructor() {
        // Derivar clave desde la variable de entorno
        const key = process.env.ENCRYPTION_KEY;
        this.algorithm = 'aes-256-gcm';
        // La clave debe ser de 32 bytes para AES-256
        this.key = Buffer.from(key, 'base64');

        if (this.key.length !== 32) {
            throw new Error('ENCRYPTION_KEY debe ser una clave de 32 bytes en base64');
        }
    }

    // ✓ SOLUCIÓN: Cifrado fuerte con AES-256-GCM
    encrypt(text) {
        if (!text) return null;

        try {
            // IV aleatorio para cada cifrado (12 bytes para GCM)
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Obtener el authentication tag
            const authTag = cipher.getAuthTag();

            // Retornar: iv + authTag + encrypted data (todo en hex)
            return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('Error al cifrar:', error);
            throw error;
        }
    }

    // Descifrar datos
    decrypt(encryptedData) {
        if (!encryptedData) return null;

        try {
            // Separar componentes
            const parts = encryptedData.split(':');
            if (parts.length !== 3) {
                throw new Error('Formato de datos cifrados inválido');
            }

            const iv = Buffer.from(parts[0], 'hex');
            const authTag = Buffer.from(parts[1], 'hex');
            const encrypted = parts[2];

            const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error('Error al descifrar:', error);
            throw error;
        }
    }
}

// Exportar instancia única
const encryptionHelper = new EncryptionHelper();

// Crear tablas con diseño seguro
db.serialize(() => {
    // ✓ SOLUCIÓN: Datos sensibles se cifrarán antes de almacenar
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            ssn_encrypted TEXT,
            credit_card_encrypted TEXT,
            medical_info_encrypted TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until DATETIME
        )
    `, (err) => {
        if (err) {
            console.error('Error creando tabla:', err);
        } else {
            console.log('✓ Tabla users creada - Campos sensibles CIFRADOS');
        }
    });

    // Tabla de sesiones seguras
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Tabla de auditoría
    db.run(`
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    `);

    console.log('✓ Tablas de seguridad adicionales creadas (sesiones, auditoría)');
});

module.exports = {
    db,
    encryptionHelper
};
