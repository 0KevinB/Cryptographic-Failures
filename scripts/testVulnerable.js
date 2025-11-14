// Script de prueba para la versión VULNERABLE
const http = require('http');

const BASE_URL = 'http://localhost:3000';

// Colores para la consola
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

function makeRequest(method, path, data = null) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, BASE_URL);
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(url, options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: JSON.parse(body)
                    });
                } catch {
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: body
                    });
                }
            });
        });

        req.on('error', reject);

        if (data) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

async function runTests() {
    console.log('═══════════════════════════════════════════════════════');
    console.log('     PRUEBAS - VERSIÓN VULNERABLE');
    console.log('═══════════════════════════════════════════════════════\n');

    try {
        // Test 1: Registro con contraseña débil
        console.log(`${colors.yellow}[TEST 1]${colors.reset} Registro con contraseña DÉBIL (123)`);
        const register1 = await makeRequest('POST', '/api/auth/register', {
            username: 'testuser',
            password: '123',  // ⚠️ Contraseña débil aceptada
            email: 'test@example.com',
            ssn: '123-45-6789',
            credit_card: '4532-1234-5678-9010',
            medical_info: 'Diabetes tipo 2'
        });
        console.log(`${colors.red}✗ VULNERABLE:${colors.reset} Contraseña débil aceptada`);
        console.log(`Respuesta: ${register1.status}\n`);

        // Test 2: Login y obtener sesión
        console.log(`${colors.yellow}[TEST 2]${colors.reset} Login y verificar token de sesión`);
        const login = await makeRequest('POST', '/api/auth/login', {
            username: 'testuser',
            password: '123'
        });
        console.log(`${colors.red}✗ VULNERABLE:${colors.reset} Token de sesión: ${login.body.sessionToken}`);
        console.log(`${colors.red}✗ PROBLEMA:${colors.reset} Token predecible (MD5 de timestamp)\n`);

        const sessionToken = login.body.sessionToken;

        // Test 3: Ver perfil con datos sensibles
        console.log(`${colors.yellow}[TEST 3]${colors.reset} Obtener perfil del usuario`);
        const profile = await makeRequest('GET', '/api/auth/profile', null);
        console.log(`${colors.red}✗ VULNERABLE:${colors.reset} Datos sensibles expuestos:`);
        console.log(`   SSN: ${profile.body.user?.ssn || 'No disponible'}`);
        console.log(`   Tarjeta: ${profile.body.user?.credit_card || 'No disponible'}`);
        console.log(`   Info médica: ${profile.body.user?.medical_info || 'No disponible'}\n`);

        // Test 4: Ver base de datos completa
        console.log(`${colors.yellow}[TEST 4]${colors.reset} Acceder al endpoint /api/debug/database`);
        const debug = await makeRequest('GET', '/api/debug/database', null);
        console.log(`${colors.red}✗ VULNERABLE:${colors.reset} Base de datos COMPLETA expuesta:`);
        if (debug.body.users && debug.body.users.length > 0) {
            const user = debug.body.users[0];
            console.log(`   Password hash (MD5): ${user.password}`);
            console.log(`   SSN en texto plano: ${user.ssn}`);
            console.log(`   Tarjeta en texto plano: ${user.credit_card}\n`);
        }

        // Test 5: Verificar headers de seguridad
        console.log(`${colors.yellow}[TEST 5]${colors.reset} Verificar headers de seguridad`);
        console.log(`${colors.red}✗ VULNERABLE:${colors.reset} Headers de seguridad ausentes:`);
        console.log(`   Strict-Transport-Security: ${debug.headers['strict-transport-security'] || 'AUSENTE'}`);
        console.log(`   Content-Security-Policy: ${debug.headers['content-security-policy'] || 'AUSENTE'}`);
        console.log(`   X-Frame-Options: ${debug.headers['x-frame-options'] || 'AUSENTE'}\n`);

        // Test 6: Intentos de login ilimitados
        console.log(`${colors.yellow}[TEST 6]${colors.reset} Probar ataques de fuerza bruta (sin rate limiting)`);
        console.log(`${colors.red}✗ VULNERABLE:${colors.reset} Haciendo 10 intentos rápidos...`);
        for (let i = 0; i < 10; i++) {
            await makeRequest('POST', '/api/auth/login', {
                username: 'testuser',
                password: 'wrong'
            });
        }
        console.log(`${colors.red}✗ PROBLEMA:${colors.reset} Todos los intentos procesados (sin rate limiting)\n`);

        console.log('═══════════════════════════════════════════════════════');
        console.log(`${colors.red}RESUMEN DE VULNERABILIDADES ENCONTRADAS:${colors.reset}`);
        console.log('1. Contraseñas débiles aceptadas');
        console.log('2. Datos sensibles en texto plano en DB');
        console.log('3. Hashing con MD5 (débil)');
        console.log('4. Tokens de sesión predecibles');
        console.log('5. Exposición de datos sensibles en respuestas');
        console.log('6. Sin rate limiting (fuerza bruta posible)');
        console.log('7. Headers de seguridad ausentes');
        console.log('8. Endpoint de debug que expone la DB completa');
        console.log('═══════════════════════════════════════════════════════\n');

    } catch (error) {
        console.error(`${colors.red}Error:${colors.reset}`, error.message);
        console.log('\n¿El servidor vulnerable está corriendo en el puerto 3000?');
        console.log('Ejecuta: npm run start:vulnerable\n');
    }
}

runTests();
