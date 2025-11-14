// VERSIÓN VULNERABLE - Servidor Principal
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const authRoutes = require('./routes/authRoutes');

const app = express();
const PORT = process.env.VULNERABLE_PORT || 3000;

// ❌ PROBLEMA 1: Sin Helmet - headers de seguridad faltantes
console.log('⚠️  VULNERABILIDAD: Sin headers de seguridad (Helmet no instalado)');

// ❌ PROBLEMA 2: CORS permisivo
app.use((req, res, next) => {
    console.log('⚠️  VULNERABILIDAD: CORS completamente abierto');
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Servir archivos estáticos (interfaz web)
app.use(express.static(path.join(__dirname, 'public')));

// ❌ PROBLEMA 3: Sin HTTPS enforcement
console.log('⚠️  VULNERABILIDAD: Servidor HTTP sin cifrado en tránsito');

// Logging de requests
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    // ❌ PROBLEMA: Logging de datos sensibles
    if (Object.keys(req.body).length > 0) {
        console.log('⚠️  VULNERABILIDAD: Logging de datos sensibles:', req.body);
    }
    next();
});

// Rutas
app.use('/api/auth', authRoutes);

// Ruta API info
app.get('/api', (req, res) => {
    res.json({
        message: '⚠️  VERSIÓN VULNERABLE - A04:2025 Cryptographic Failures Demo',
        warning: 'Esta versión contiene MÚLTIPLES vulnerabilidades criptográficas',
        vulnerabilities: [
            '1. Contraseñas hasheadas con MD5 (débil)',
            '2. Datos sensibles almacenados en texto plano',
            '3. Sin cifrado en tránsito (HTTP)',
            '4. Tokens de sesión predecibles',
            '5. Cookies sin flags de seguridad',
            '6. Sin rate limiting (fuerza bruta posible)',
            '7. Exposición de datos sensibles en respuestas',
            '8. Sin validación de contraseñas fuertes',
            '9. Logging de información sensible',
            '10. Headers de seguridad ausentes'
        ],
        endpoints: {
            register: 'POST /api/auth/register',
            login: 'POST /api/auth/login',
            profile: 'GET /api/auth/profile',
            users: 'GET /api/auth/users',
            logout: 'POST /api/auth/logout'
        }
    });
});

// Ruta para ver la base de datos (SOLO PARA DEMO)
app.get('/api/debug/database', (req, res) => {
    const db = require('./config/database');

    db.all('SELECT * FROM users', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        console.log('⚠️  VULNERABILIDAD: Endpoint que expone TODA la base de datos');
        res.json({
            warning: 'DATOS EN TEXTO PLANO - Esto demuestra el riesgo',
            users: rows
        });
    });
});

// Manejo de errores
app.use((err, req, res, next) => {
    console.error('Error:', err);
    // ❌ PROBLEMA: Exposición de stack traces
    res.status(500).json({
        success: false,
        message: err.message,
        stack: err.stack  // ❌ Expuesto en producción
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log('═══════════════════════════════════════════════════════');
    console.log('⚠️  SERVIDOR VULNERABLE INICIADO');
    console.log(`🔓 Puerto: ${PORT}`);
    console.log('🔓 Protocolo: HTTP (sin cifrado)');
    console.log(`🌐 Interfaz Web: http://localhost:${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
    console.log('⚠️  ADVERTENCIA: Esta versión es INTENCIONALMENTE insegura');
    console.log('═══════════════════════════════════════════════════════');
});

module.exports = app;
