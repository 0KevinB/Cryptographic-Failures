// Script para probar la configuración de cifrado
require('dotenv').config();
const crypto = require('crypto');

console.log('═══════════════════════════════════════════════════════');
console.log('Test de Configuración de Cifrado');
console.log('═══════════════════════════════════════════════════════\n');

// Verificar variables de entorno
console.log('1. Verificando variables de entorno...');
console.log(`   SESSION_SECRET: ${process.env.SESSION_SECRET ? '✓ Configurada' : '✗ NO configurada'}`);
console.log(`   ENCRYPTION_KEY: ${process.env.ENCRYPTION_KEY ? '✓ Configurada' : '✗ NO configurada'}`);

if (!process.env.ENCRYPTION_KEY) {
    console.log('\n❌ ERROR: ENCRYPTION_KEY no está configurada');
    console.log('\nSolución:');
    console.log('1. Ejecuta: node scripts/generateKeys.js');
    console.log('2. Copia la ENCRYPTION_KEY generada');
    console.log('3. Pégala en el archivo .env');
    process.exit(1);
}

console.log('\n2. Verificando longitud de ENCRYPTION_KEY...');
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
console.log(`   Longitud esperada: 32 bytes`);
console.log(`   Longitud actual: ${key.length} bytes`);

if (key.length !== 32) {
    console.log('\n❌ ERROR: ENCRYPTION_KEY tiene longitud incorrecta');
    console.log('\nSolución:');
    console.log('1. Ejecuta: node scripts/generateKeys.js');
    console.log('2. Genera una NUEVA clave');
    console.log('3. Reemplaza la clave en el archivo .env');
    process.exit(1);
}

console.log('   ✓ Longitud correcta');

// Probar cifrado/descifrado
console.log('\n3. Probando cifrado/descifrado...');
try {
    const algorithm = 'aes-256-gcm';
    const testData = 'Datos de prueba 123-45-6789';

    // Cifrar
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(testData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    const encryptedData = iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    console.log(`   Dato original: "${testData}"`);
    console.log(`   Dato cifrado: ${encryptedData.substring(0, 50)}...`);

    // Descifrar
    const parts = encryptedData.split(':');
    const ivDecrypt = Buffer.from(parts[0], 'hex');
    const authTagDecrypt = Buffer.from(parts[1], 'hex');
    const encryptedText = parts[2];

    const decipher = crypto.createDecipheriv(algorithm, key, ivDecrypt);
    decipher.setAuthTag(authTagDecrypt);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    console.log(`   Dato descifrado: "${decrypted}"`);

    if (decrypted === testData) {
        console.log('   ✓ Cifrado/Descifrado funciona correctamente');
    } else {
        console.log('   ✗ Error: El dato descifrado no coincide');
        process.exit(1);
    }
} catch (error) {
    console.log(`   ✗ Error en cifrado/descifrado: ${error.message}`);
    process.exit(1);
}

// Probar bcrypt
console.log('\n4. Probando bcrypt...');
try {
    const bcrypt = require('bcrypt');
    const testPassword = 'TestPassword123!';

    const hash = bcrypt.hashSync(testPassword, 12);
    console.log(`   Password original: "${testPassword}"`);
    console.log(`   Hash bcrypt: ${hash.substring(0, 30)}...`);

    const match = bcrypt.compareSync(testPassword, hash);
    console.log(`   Verificación: ${match ? '✓ Correcta' : '✗ Incorrecta'}`);
} catch (error) {
    console.log(`   ✗ Error en bcrypt: ${error.message}`);
    process.exit(1);
}

// Probar conexión a base de datos
console.log('\n5. Probando conexión a base de datos...');
try {
    const sqlite3 = require('sqlite3').verbose();
    const path = require('path');
    const dbPath = path.join(__dirname, '..', 'secure', 'database', 'secure.db');

    const db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.log(`   ✗ Error al conectar: ${err.message}`);
            process.exit(1);
        } else {
            console.log('   ✓ Conexión exitosa');

            // Verificar tablas
            db.all("SELECT name FROM sqlite_master WHERE type='table'", [], (err, tables) => {
                if (err) {
                    console.log(`   ✗ Error al listar tablas: ${err.message}`);
                } else {
                    console.log(`   Tablas encontradas: ${tables.map(t => t.name).join(', ')}`);
                }
                db.close();

                console.log('\n═══════════════════════════════════════════════════════');
                console.log('✓ TODAS LAS PRUEBAS PASARON');
                console.log('═══════════════════════════════════════════════════════');
                console.log('\nEl servidor seguro debería funcionar correctamente.');
                console.log('Si aún tienes problemas, revisa:');
                console.log('1. La consola del navegador (F12) para errores de JavaScript');
                console.log('2. La consola del servidor para errores al registrar usuarios');
            });
        }
    });
} catch (error) {
    console.log(`   ✗ Error: ${error.message}`);
    process.exit(1);
}
