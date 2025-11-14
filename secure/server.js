// VERSIÓN SEGURA - Servidor Principal
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');

const authRoutes = require('./routes/authRoutes');
const User = require('./models/User');

const app = express();
const PORT = process.env.SECURE_PORT || 3001;

// Validar configuración requerida
if (!process.env.SESSION_SECRET) {
    console.error('❌ ERROR: SESSION_SECRET no está configurada');
    process.exit(1);
}

if (!process.env.ENCRYPTION_KEY) {
    console.error('❌ ERROR: ENCRYPTION_KEY no está configurada');
    process.exit(1);
}

// ✓ SOLUCIÓN 1: Usar Helmet para headers de seguridad
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'", "'unsafe-hashes'"], // Permitir event handlers inline
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
}));

// ✓ SOLUCIÓN 2: CORS restrictivo
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3001'];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// Middlewares
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Servir archivos estáticos (interfaz web)
app.use(express.static(path.join(__dirname, 'public')));

// ✓ SOLUCIÓN 3: Middleware para logging seguro (sin datos sensibles)
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const method = req.method;
    const path = req.path;
    const ip = req.ip;

    // NO registrar el body completo para evitar logging de datos sensibles
    console.log(`[${timestamp}] ${method} ${path} - IP: ${ip}`);
    next();
});

// ✓ SOLUCIÓN 4: Middleware de seguridad adicional
app.disable('x-powered-by'); // Ocultar que usamos Express

// Rutas
app.use('/api/auth', authRoutes);

// Ruta API info
app.get('/api', (req, res) => {
    res.json({
        message: '✓ VERSIÓN SEGURA - A04:2025 Cryptographic Failures Demo',
        security: 'Esta versión implementa múltiples controles de seguridad',
        protections: [
            '✓ Contraseñas con bcrypt (12 rounds)',
            '✓ Datos sensibles cifrados con AES-256-GCM',
            '✓ HTTPS enforcement (en producción)',
            '✓ Tokens de sesión criptográficamente seguros',
            '✓ Cookies con HTTPOnly, Secure, SameSite',
            '✓ Rate limiting contra fuerza bruta',
            '✓ Enmascaramiento de datos sensibles',
            '✓ Validación de contraseñas fuertes',
            '✓ Logging seguro (sin datos sensibles)',
            '✓ Headers de seguridad (Helmet)',
            '✓ Bloqueo de cuenta tras intentos fallidos',
            '✓ Auditoría de acceso a datos',
            '✓ Expiración de sesiones',
            '✓ Reautenticación para datos sensibles'
        ],
        endpoints: {
            register: 'POST /api/auth/register',
            login: 'POST /api/auth/login',
            profile: 'GET /api/auth/profile',
            sensitiveData: 'POST /api/auth/sensitive-data (requiere password)',
            users: 'GET /api/auth/users',
            logout: 'POST /api/auth/logout'
        }
    });
});

// Ruta de salud
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ✓ SOLUCIÓN: Manejo de errores sin exponer detalles internos
app.use((err, req, res, next) => {
    console.error('Error interno:', err);

    // NO exponer stack trace en producción
    const response = {
        success: false,
        message: 'Error interno del servidor'
    };

    if (process.env.NODE_ENV === 'development') {
        response.error = err.message;
    }

    res.status(500).json(response);
});

// Manejo de rutas no encontradas
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Ruta no encontrada'
    });
});

// ✓ SOLUCIÓN: Tarea periódica para limpiar sesiones expiradas
setInterval(() => {
    User.cleanExpiredSessions((err, deletedCount) => {
        if (err) {
            console.error('Error al limpiar sesiones:', err);
        } else if (deletedCount > 0) {
            console.log(`Limpieza: ${deletedCount} sesiones expiradas eliminadas`);
        }
    });
}, 60 * 60 * 1000); // Cada hora

// Iniciar servidor
const server = app.listen(PORT, () => {
    console.log('═══════════════════════════════════════════════════════');
    console.log('✓ SERVIDOR SEGURO INICIADO');
    console.log(`🔒 Puerto: ${PORT}`);
    console.log(`🔒 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log('🔒 Protocolo: HTTP (usar HTTPS en producción)');
    console.log(`🌐 Interfaz Web: http://localhost:${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
    console.log('✓ Controles de seguridad activos');
    console.log('═══════════════════════════════════════════════════════');
});

// Manejo de cierre graceful
process.on('SIGTERM', () => {
    console.log('Señal SIGTERM recibida. Cerrando servidor...');
    server.close(() => {
        console.log('Servidor cerrado correctamente');
        process.exit(0);
    });
});

module.exports = app;
