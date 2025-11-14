// Script para generar claves criptográficas seguras
const crypto = require('crypto');

console.log('═══════════════════════════════════════════════════════');
console.log('Generador de Claves Criptográficas Seguras');
console.log('═══════════════════════════════════════════════════════\n');

// Generar SESSION_SECRET (64 bytes en hex)
const sessionSecret = crypto.randomBytes(64).toString('hex');
console.log('SESSION_SECRET (para sesiones):');
console.log(sessionSecret);
console.log('');

// Generar ENCRYPTION_KEY (32 bytes en base64 para AES-256)
const encryptionKey = crypto.randomBytes(32).toString('base64');
console.log('ENCRYPTION_KEY (para cifrado de datos):');
console.log(encryptionKey);
console.log('');

console.log('═══════════════════════════════════════════════════════');
console.log('Instrucciones:');
console.log('1. Copia el archivo .env.example a .env');
console.log('2. Pega las claves generadas arriba en tu archivo .env');
console.log('3. NUNCA compartas estas claves ni las subas a Git');
console.log('═══════════════════════════════════════════════════════');
