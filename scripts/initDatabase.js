// Script para inicializar las bases de datos
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

console.log('═══════════════════════════════════════════════════════');
console.log('Inicializando Bases de Datos');
console.log('═══════════════════════════════════════════════════════\n');

// Crear directorios si no existen
const vulnerableDbDir = path.join(__dirname, '..', 'vulnerable', 'database');
const secureDbDir = path.join(__dirname, '..', 'secure', 'database');

if (!fs.existsSync(vulnerableDbDir)) {
    fs.mkdirSync(vulnerableDbDir, { recursive: true });
    console.log('✓ Directorio creado: vulnerable/database');
}

if (!fs.existsSync(secureDbDir)) {
    fs.mkdirSync(secureDbDir, { recursive: true });
    console.log('✓ Directorio creado: secure/database');
}

console.log('');

// ====================================
// VERSIÓN VULNERABLE
// ====================================
console.log('⚠️  Creando base de datos VULNERABLE...');

const vulnerableDbPath = path.join(vulnerableDbDir, 'vulnerable.db');

// Eliminar DB existente si hay
if (fs.existsSync(vulnerableDbPath)) {
    fs.unlinkSync(vulnerableDbPath);
    console.log('   - Base de datos anterior eliminada');
}

const vulnerableDb = new sqlite3.Database(vulnerableDbPath, (err) => {
    if (err) {
        console.error('❌ Error al crear base de datos vulnerable:', err);
        process.exit(1);
    }
});

vulnerableDb.serialize(() => {
    // Crear tabla de usuarios
    vulnerableDb.run(`
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
            console.error('❌ Error creando tabla users:', err);
        } else {
            console.log('✓ Tabla "users" creada (datos en texto plano)');
        }
    });

    // Crear tabla de sesiones
    vulnerableDb.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `, (err) => {
        if (err) {
            console.error('❌ Error creando tabla sessions:', err);
        } else {
            console.log('✓ Tabla "sessions" creada');
        }
    });
});

vulnerableDb.close((err) => {
    if (err) {
        console.error('❌ Error al cerrar base de datos vulnerable:', err);
    } else {
        console.log('✓ Base de datos vulnerable cerrada correctamente\n');

        // Después de cerrar la vulnerable, crear la segura
        createSecureDatabase();
    }
});

// ====================================
// VERSIÓN SEGURA
// ====================================
function createSecureDatabase() {
    console.log('🔒 Creando base de datos SEGURA...');

    const secureDbPath = path.join(secureDbDir, 'secure.db');

    // Eliminar DB existente si hay
    if (fs.existsSync(secureDbPath)) {
        fs.unlinkSync(secureDbPath);
        console.log('   - Base de datos anterior eliminada');
    }

    const secureDb = new sqlite3.Database(secureDbPath, (err) => {
        if (err) {
            console.error('❌ Error al crear base de datos segura:', err);
            process.exit(1);
        }
    });

    secureDb.serialize(() => {
        // Crear tabla de usuarios con campos cifrados
        secureDb.run(`
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
                console.error('❌ Error creando tabla users:', err);
            } else {
                console.log('✓ Tabla "users" creada (con campos cifrados)');
            }
        });

        // Crear tabla de sesiones seguras
        secureDb.run(`
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
        `, (err) => {
            if (err) {
                console.error('❌ Error creando tabla sessions:', err);
            } else {
                console.log('✓ Tabla "sessions" creada (con expiración)');
            }
        });

        // Crear tabla de auditoría
        secureDb.run(`
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        `, (err) => {
            if (err) {
                console.error('❌ Error creando tabla audit_log:', err);
            } else {
                console.log('✓ Tabla "audit_log" creada (auditoría)');
            }
        });
    });

    secureDb.close((err) => {
        if (err) {
            console.error('❌ Error al cerrar base de datos segura:', err);
        } else {
            console.log('✓ Base de datos segura cerrada correctamente\n');
            showSummary();
        }
    });
}

// ====================================
// RESUMEN
// ====================================
function showSummary() {
    console.log('═══════════════════════════════════════════════════════');
    console.log('✓ Inicialización Completada');
    console.log('═══════════════════════════════════════════════════════\n');

    console.log('Bases de datos creadas:');
    console.log('');
    console.log('1. VULNERABLE:');
    console.log(`   📁 Ruta: vulnerable/database/vulnerable.db`);
    console.log('   📊 Tablas: users, sessions');
    console.log('   ⚠️  Datos: EN TEXTO PLANO');
    console.log('');
    console.log('2. SEGURA:');
    console.log(`   📁 Ruta: secure/database/secure.db`);
    console.log('   📊 Tablas: users, sessions, audit_log');
    console.log('   🔒 Datos: CIFRADOS con AES-256-GCM');
    console.log('');
    console.log('═══════════════════════════════════════════════════════');
    console.log('Próximos pasos:');
    console.log('');
    console.log('1. npm run start:vulnerable');
    console.log('   → Abrir http://localhost:3000');
    console.log('');
    console.log('2. npm run start:secure');
    console.log('   → Abrir http://localhost:3001');
    console.log('═══════════════════════════════════════════════════════\n');
}
