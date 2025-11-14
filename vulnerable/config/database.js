// VERSIÓN VULNERABLE - Base de Datos
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'database', 'vulnerable.db');

// Crear conexión a la base de datos
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
    } else {
        console.log('✗ Conectado a base de datos VULNERABLE (sin cifrado)');
    }
});

// Crear tabla de usuarios con PROBLEMAS DE SEGURIDAD
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            ssn TEXT,
            credit_card TEXT,
            medical_info TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creando tabla:', err);
        } else {
            console.log('✗ Tabla users creada - ALMACENA DATOS EN TEXTO PLANO');
        }
    });

    // Tabla de sesiones (insegura)
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
});

module.exports = db;
