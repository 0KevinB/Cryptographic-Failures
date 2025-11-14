# Demostración Práctica: A04:2025 - Cryptographic Failures

## Proyecto Completo con Express.js, MVC y SQLite

Este proyecto demuestra de forma práctica las vulnerabilidades relacionadas con **Cryptographic Failures** (Fallos Criptográficos) del OWASP Top 10:2025, implementando dos versiones completas de una aplicación:

- **Versión VULNERABLE**: Con múltiples fallos criptográficos intencionales
- **Versión SEGURA**: Con implementaciones correctas de seguridad

---

## Índice

- [Estructura del Proyecto](#estructura-del-proyecto)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Configuración](#configuración)
- [Ejecución](#ejecución)
- [Comparación Detallada](#comparación-detallada)
- [Endpoints de la API](#endpoints-de-la-api)
- [Testing](#testing)
- [Arquitectura MVC](#arquitectura-mvc)
- [Lecciones Aprendidas](#lecciones-aprendidas)

---

## Estructura del Proyecto

```
Owasp/
├── vulnerable/                 # Versión VULNERABLE
│   ├── config/
│   │   └── database.js        # Configuración DB sin cifrado
│   ├── models/
│   │   └── User.js            # Modelo con MD5 y texto plano
│   ├── controllers/
│   │   └── authController.js  # Controlador inseguro
│   ├── routes/
│   │   └── authRoutes.js      # Rutas sin rate limiting
│   ├── database/
│   │   └── vulnerable.db      # Base de datos vulnerable
│   └── server.js              # Servidor HTTP sin protección
│
├── secure/                     # Versión SEGURA
│   ├── config/
│   │   └── database.js        # Configuración con AES-256-GCM
│   ├── models/
│   │   └── User.js            # Modelo con bcrypt y cifrado
│   ├── controllers/
│   │   └── authController.js  # Controlador con validaciones
│   ├── routes/
│   │   └── authRoutes.js      # Rutas con rate limiting
│   ├── database/
│   │   └── secure.db          # Base de datos segura
│   └── server.js              # Servidor con Helmet y seguridad
│
├── scripts/
│   ├── generateKeys.js        # Generador de claves criptográficas
│   ├── testVulnerable.js      # Tests para versión vulnerable
│   └── testSecure.js          # Tests para versión segura
│
├── package.json
├── .env.example
├── .gitignore
├── README.md                   # Documentación teórica
└── PROJECT_README.md           # Este archivo (guía práctica)
```

---

## Requisitos

- **Node.js** >= 14.x
- **npm** >= 6.x
- **Sistema Operativo**: Windows, Linux, macOS

---

## Instalación

### 1. Clonar o descargar el proyecto

```bash
cd "C:\Users\kevin\Documents\Github\Seguridad de la Informacion\Owasp"
```

### 2. Instalar dependencias

```bash
npm install
```

Esto instalará:

- `express` - Framework web
- `sqlite3` - Base de datos
- `bcrypt` - Hashing seguro de contraseñas
- `helmet` - Headers de seguridad
- `express-rate-limit` - Limitación de peticiones
- `validator` - Validación de datos
- `dotenv` - Variables de entorno

---

## Configuración

### 1. Generar claves criptográficas

```bash
node scripts/generateKeys.js
```

Esto generará:

- `SESSION_SECRET`: Para firmar sesiones (64 bytes hex)
- `ENCRYPTION_KEY`: Para cifrar datos (32 bytes base64 para AES-256)

**Ejemplo de salida:**

```
SESSION_SECRET (para sesiones):
a1b2c3d4e5f6789...

ENCRYPTION_KEY (para cifrado de datos):
XyZ123AbC456DeF789...==
```

### 2. Crear archivo `.env`

Copia `.env.example` a `.env`:

```bash
copy .env.example .env
```

Edita `.env` y pega las claves generadas:

```env
# .env
SESSION_SECRET=tu_clave_generada_aqui
ENCRYPTION_KEY=tu_clave_de_cifrado_aqui

SECURE_PORT=3001
VULNERABLE_PORT=3000
NODE_ENV=development
```

⚠️ **IMPORTANTE**: NUNCA subas el archivo `.env` a Git

---

## Ejecución

### Servidor VULNERABLE (Puerto 3000)

```bash
npm run start:vulnerable
```

Salida esperada:

```
═══════════════════════════════════════════════════════
⚠️  SERVIDOR VULNERABLE INICIADO
🔓 Puerto: 3000
🔓 Protocolo: HTTP (sin cifrado)
⚠️  ADVERTENCIA: Esta versión es INTENCIONALMENTE insegura
═══════════════════════════════════════════════════════
```

Accede a: http://localhost:3000

### Servidor SEGURO (Puerto 3001)

```bash
npm run start:secure
```

Salida esperada:

```
═══════════════════════════════════════════════════════
✓ SERVIDOR SEGURO INICIADO
🔒 Puerto: 3001
🔒 Ambiente: development
✓ Controles de seguridad activos
═══════════════════════════════════════════════════════
```

Accede a: http://localhost:3001

---

## Comparación Detallada

### 1. Almacenamiento de Contraseñas

#### ❌ VULNERABLE

```javascript
// vulnerable/models/User.js
static hashPassword(password) {
    console.log('⚠️  VULNERABILIDAD: Usando MD5 para contraseñas');
    return crypto.createHash('md5').update(password).digest('hex');
}
```

**Problemas:**

- MD5 es un algoritmo débil y obsoleto
- No usa salt (múltiples usuarios con misma contraseña tienen mismo hash)
- Vulnerable a rainbow tables
- Se puede descifrar en segundos

**Ejemplo en BD:**

```sql
-- Base de datos vulnerable
username: admin
password: 5f4dcc3b5aa765d61d8327deb882cf99  -- Es "password" en MD5
```

#### ✅ SEGURO

```javascript
// secure/models/User.js
static async hashPassword(password) {
    const saltRounds = 12;  // Factor de costo
    return await bcrypt.hash(password, saltRounds);
}
```

**Protecciones:**

- bcrypt es diseñado específicamente para contraseñas
- Salt único generado automáticamente
- Factor de costo ajustable (12 rounds = ~250ms)
- Resistente a ataques de fuerza bruta

**Ejemplo en BD:**

```sql
-- Base de datos segura
username: admin
password_hash: $2b$12$K1lC8h3TzKPu.vQFQH7VUOz5QN6xW... (60 caracteres)
```

---

### 2. Almacenamiento de Datos Sensibles

#### ❌ VULNERABLE

```javascript
// vulnerable/models/User.js
const query = `
    INSERT INTO users (username, password, email, ssn, credit_card, medical_info)
    VALUES (?, ?, ?, ?, ?, ?)
`;

db.run(query, [username, hashedPassword, email, ssn, credit_card, medical_info]);
```

**Problemas:**

- Datos sensibles almacenados en **texto plano**
- SSN, tarjetas de crédito, información médica expuestos
- Cualquier acceso a la BD compromete todos los datos

**Visualización en BD:**

```
id | username | ssn         | credit_card      | medical_info
1  | john     | 123-45-6789 | 4532123456789010 | Diabetes tipo 2
```

#### ✅ SEGURO

```javascript
// secure/models/User.js
// Cifrar datos sensibles con AES-256-GCM
const ssnEncrypted = ssn ? encryptionHelper.encrypt(ssn) : null;
const creditCardEncrypted = credit_card ? encryptionHelper.encrypt(credit_card) : null;
const medicalInfoEncrypted = medical_info ? encryptionHelper.encrypt(medical_info) : null;

const query = `
    INSERT INTO users (username, password_hash, email,
                      ssn_encrypted, credit_card_encrypted, medical_info_encrypted)
    VALUES (?, ?, ?, ?, ?, ?)
`;
```

**Implementación del cifrado:**

```javascript
// secure/config/database.js
class EncryptionHelper {
  constructor() {
    this.algorithm = 'aes-256-gcm'; // Cifrado autenticado
    this.key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
  }

  encrypt(text) {
    const iv = crypto.randomBytes(12); // IV aleatorio
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag(); // Tag de autenticación

    // Retornar: iv + authTag + datos cifrados
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }

  decrypt(encryptedData) {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
```

**Protecciones:**

- **AES-256-GCM**: Cifrado simétrico de grado militar
- **IV aleatorio**: Cada cifrado es único aunque el texto sea el mismo
- **Authentication tag**: Verifica integridad (detecta manipulación)
- **Clave de 256 bits**: Imposible de romper por fuerza bruta

**Visualización en BD:**

```
id | username | ssn_encrypted
1  | john     | a1b2c3d4e5f6:1a2b3c4d:9f8e7d6c5b4a3210...
```

---

### 3. Tokens de Sesión

#### ❌ VULNERABLE

```javascript
// vulnerable/models/User.js
static createSession(userId, callback) {
    console.log('⚠️  VULNERABILIDAD: Token de sesión predecible');

    // Token débil basado en timestamp
    const sessionToken = crypto.createHash('md5')
        .update(userId.toString() + Date.now().toString())
        .digest('hex');

    // Almacenar en BD
}
```

**Problemas:**

- Token predecible (basado en timestamp)
- MD5 es débil
- Sin expiración
- Fácil de adivinar o generar por fuerza bruta

**Ejemplo de tokens:**

```
Usuario 1: 5d41402abc4b2a76b9719d911017c592
Usuario 2: 7d793037a0760186574b0282f2f435e7
// Patrón predecible basado en tiempo
```

#### ✅ SEGURO

```javascript
// secure/models/User.js
static createSession(userId, ipAddress, userAgent, callback) {
    // Token de 32 bytes (256 bits) completamente aleatorio
    const sessionToken = crypto.randomBytes(32).toString('hex');

    // Expiración: 24 horas
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    const query = `
        INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    `;

    // Guardar con metadata de seguridad
}
```

**Protecciones:**

- **256 bits de aleatoriedad** criptográficamente segura
- **Expiración automática** tras 24 horas
- **Auditoría**: IP y User-Agent registrados
- **Verificación de expiración** en cada petición

**Ejemplo de tokens:**

```
3f4a9c7b2e1d8f5a6c9b0e3d7a4f1c8e2b5d8a1f4c7e0b3d6a9f2c5e8b1d4a7f
9e2b5d8a1f4c7e0b3d6a9f2c5e8b1d4a7f3c6a9e2b5d8a1f4c7e0b3d6a9f2c5
// Completamente impredecibles
```

---

### 4. Cookies de Sesión

#### ❌ VULNERABLE

```javascript
// vulnerable/controllers/authController.js
res.cookie('session_token', sessionToken);
// Sin flags de seguridad
```

**Problemas:**

- Accesible desde JavaScript (XSS)
- Enviada sobre HTTP (sin cifrado)
- Sin protección CSRF
- Sin expiración

**Header de respuesta:**

```http
Set-Cookie: session_token=abc123; Path=/
```

#### ✅ SEGURO

```javascript
// secure/controllers/authController.js
res.cookie('session_token', sessionToken, {
  httpOnly: true, // No accesible desde JavaScript
  secure: process.env.NODE_ENV === 'production', // Solo HTTPS
  sameSite: 'strict', // Protección contra CSRF
  maxAge: 24 * 60 * 60 * 1000, // 24 horas
});
```

**Header de respuesta:**

```http
Set-Cookie: session_token=abc123; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400
```

**Protecciones:**

- **HttpOnly**: Bloquea acceso desde JavaScript (previene XSS)
- **Secure**: Solo se envía por HTTPS (previene intercepción)
- **SameSite=Strict**: Previene CSRF
- **MaxAge**: Expiración automática

---

### 5. Validación de Contraseñas

#### ❌ VULNERABLE

```javascript
// vulnerable/controllers/authController.js
static register(req, res) {
    const { username, password, email } = req.body;

    // Sin validación de contraseña
    if (!username || !password || !email) {
        return res.status(400).json({ message: 'Faltan campos' });
    }

    // Acepta contraseñas como "123", "password", etc.
    User.create({ username, password, email }, callback);
}
```

**Acepta:**

- `123`
- `password`
- `12345678`

#### ✅ SEGURO

```javascript
// secure/models/User.js
static validatePassword(password) {
    const errors = [];

    if (password.length < 12) {
        errors.push('Contraseña debe tener al menos 12 caracteres');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Debe contener al menos una mayúscula');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Debe contener al menos una minúscula');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Debe contener al menos un número');
    }
    if (!/[!@#$%^&*]/.test(password)) {
        errors.push('Debe contener un carácter especial (!@#$%^&*)');
    }

    return { valid: errors.length === 0, errors };
}
```

**Requiere:**

- Mínimo 12 caracteres
- Al menos una mayúscula
- Al menos una minúscula
- Al menos un número
- Al menos un carácter especial

**Ejemplo válido:** `MySecureP@ssw0rd2024!`

---

### 6. Rate Limiting

#### ❌ VULNERABLE

```javascript
// vulnerable/routes/authRoutes.js
router.post('/login', AuthController.login);
// Sin rate limiting
```

**Problema:**

- Permite intentos ilimitados de login
- Vulnerable a ataques de fuerza bruta
- No hay protección contra bots

**Ataque posible:**

```python
# Ataque de fuerza bruta
for password in password_list:
    requests.post('/api/auth/login', {
        'username': 'admin',
        'password': password
    })
# Sin límite de intentos
```

#### ✅ SEGURO

```javascript
// secure/routes/authRoutes.js
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // máximo 5 intentos
  message: {
    success: false,
    message: 'Demasiados intentos. Intente más tarde.',
  },
});

router.post('/login', loginLimiter, AuthController.login);
```

**Protección adicional:**

```javascript
// secure/models/User.js - Bloqueo de cuenta
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
    // Bloquea cuenta por 15 minutos tras 5 intentos fallidos
}
```

---

### 7. Headers de Seguridad

#### ❌ VULNERABLE

```javascript
// vulnerable/server.js
const express = require('express');
const app = express();
// Sin Helmet ni headers de seguridad
```

**Headers ausentes:**

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Powered-By: Express  ⚠️ Revela tecnología
```

#### ✅ SEGURO

```javascript
// secure/server.js
const helmet = require('helmet');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

app.disable('x-powered-by');
```

**Headers de respuesta:**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

**Protecciones:**

- **HSTS**: Fuerza HTTPS
- **CSP**: Previene XSS
- **X-Frame-Options**: Previene clickjacking
- **X-Content-Type-Options**: Previene MIME sniffing

---

### 8. Exposición de Datos Sensibles

#### ❌ VULNERABLE

```javascript
// vulnerable/controllers/authController.js
static getProfile(req, res) {
    User.verifySession(sessionToken, (err, user) => {
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                ssn: user.ssn,                    // ❌ Expuesto
                credit_card: user.credit_card,    // ❌ Expuesto
                medical_info: user.medical_info   // ❌ Expuesto
            }
        });
    });
}
```

**Respuesta API:**

```json
{
  "user": {
    "ssn": "123-45-6789",
    "credit_card": "4532-1234-5678-9010",
    "medical_info": "Diabetes tipo 2"
  }
}
```

#### ✅ SEGURO

```javascript
// secure/controllers/authController.js
static getProfile(req, res) {
    User.findById(user.id, true, (err, userData) => {
        // Enmascarar datos sensibles
        const maskedData = {
            id: userData.id,
            username: userData.username,
            ssn: userData.ssn ? '***-**-' + userData.ssn.slice(-4) : null,
            credit_card: userData.credit_card ? '**** **** **** ' + userData.credit_card.slice(-4) : null,
            medical_info: userData.medical_info ? '[Información médica disponible]' : null
        };

        res.json({ success: true, user: maskedData });
    });
}
```

**Respuesta API:**

```json
{
  "user": {
    "ssn": "***-**-6789",
    "credit_card": "**** **** **** 9010",
    "medical_info": "[Información médica disponible]"
  }
}
```

**Acceso completo (requiere reautenticación):**

```javascript
// secure/controllers/authController.js
static getSensitiveData(req, res) {
    const { password } = req.body;

    // Verificar contraseña antes de mostrar datos completos
    const passwordMatch = await User.verifyPassword(password, user.password_hash);

    if (!passwordMatch) {
        User.logAudit(user.id, 'SENSITIVE_DATA_ACCESS_DENIED', req.ip);
        return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // Log de auditoría
    User.logAudit(user.id, 'SENSITIVE_DATA_ACCESSED', req.ip);

    // Retornar datos completos
}
```

---

### 9. Auditoría y Logging

#### ❌ VULNERABLE

```javascript
// vulnerable/server.js
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  // ⚠️ PROBLEMA: Logging de datos sensibles
  if (Object.keys(req.body).length > 0) {
    console.log('Body:', req.body); // Incluye contraseñas, SSN, etc.
  }
  next();
});
```

**Log vulnerable:**

```
POST /api/auth/login
Body: { username: 'admin', password: 'MyPassword123!' }
POST /api/auth/register
Body: { ssn: '123-45-6789', credit_card: '4532...' }
```

#### ✅ SEGURO

```javascript
// secure/server.js
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;
  const ip = req.ip;

  // NO registrar el body para evitar logging de datos sensibles
  console.log(`[${timestamp}] ${method} ${path} - IP: ${ip}`);
  next();
});
```

**Log seguro:**

```
[2024-11-13T10:30:45.123Z] POST /api/auth/login - IP: 127.0.0.1
[2024-11-13T10:31:12.456Z] GET /api/auth/profile - IP: 127.0.0.1
```

**Tabla de auditoría:**

```javascript
// secure/models/User.js
static logAudit(userId, action, ipAddress, details) {
    const query = `
        INSERT INTO audit_log (user_id, action, ip_address, details)
        VALUES (?, ?, ?, ?)
    `;

    db.run(query, [userId, action, ipAddress, details]);
}
```

**Eventos auditados:**

- `USER_CREATED`
- `SESSION_CREATED`
- `LOGIN_FAILED`
- `LOGIN_BLOCKED`
- `PROFILE_VIEWED`
- `SENSITIVE_DATA_ACCESSED`
- `SENSITIVE_DATA_ACCESS_DENIED`

---

## Endpoints de la API

### Versión VULNERABLE (Puerto 3000)

| Método | Endpoint              | Descripción                        |
| ------ | --------------------- | ---------------------------------- |
| GET    | `/`                   | Información de la API              |
| POST   | `/api/auth/register`  | Registro de usuario                |
| POST   | `/api/auth/login`     | Login                              |
| GET    | `/api/auth/profile`   | Perfil (con datos sensibles)       |
| GET    | `/api/auth/users`     | Lista TODOS los usuarios con datos |
| POST   | `/api/auth/logout`    | Logout                             |
| GET    | `/api/debug/database` | ⚠️ Expone toda la BD               |

### Versión SEGURA (Puerto 3001)

| Método | Endpoint                   | Descripción                         |
| ------ | -------------------------- | ----------------------------------- |
| GET    | `/`                        | Información de la API               |
| POST   | `/api/auth/register`       | Registro (validación estricta)      |
| POST   | `/api/auth/login`          | Login (rate limited)                |
| GET    | `/api/auth/profile`        | Perfil (datos enmascarados)         |
| POST   | `/api/auth/sensitive-data` | Datos completos (requiere password) |
| GET    | `/api/auth/users`          | Lista usuarios (solo info pública)  |
| POST   | `/api/auth/logout`         | Logout                              |
| GET    | `/health`                  | Estado del servidor                 |

---

## Testing

### Probar versión VULNERABLE

```bash
npm run test:vulnerable
```

**Salida esperada:**

```
═══════════════════════════════════════════════════════
     PRUEBAS - VERSIÓN VULNERABLE
═══════════════════════════════════════════════════════

[TEST 1] Registro con contraseña DÉBIL (123)
✗ VULNERABLE: Contraseña débil aceptada

[TEST 2] Login y verificar token de sesión
✗ VULNERABLE: Token de sesión: 5d41402abc4b2a76b9719d911017c592
✗ PROBLEMA: Token predecible (MD5 de timestamp)

[TEST 3] Obtener perfil del usuario
✗ VULNERABLE: Datos sensibles expuestos:
   SSN: 123-45-6789
   Tarjeta: 4532-1234-5678-9010
   Info médica: Diabetes tipo 2

[TEST 4] Acceder al endpoint /api/debug/database
✗ VULNERABLE: Base de datos COMPLETA expuesta

[TEST 5] Verificar headers de seguridad
✗ VULNERABLE: Headers de seguridad ausentes

[TEST 6] Probar ataques de fuerza bruta
✗ VULNERABLE: Sin rate limiting

═══════════════════════════════════════════════════════
RESUMEN DE VULNERABILIDADES ENCONTRADAS:
1. Contraseñas débiles aceptadas
2. Datos sensibles en texto plano en DB
3. Hashing con MD5 (débil)
4. Tokens de sesión predecibles
5. Exposición de datos sensibles en respuestas
6. Sin rate limiting
7. Headers de seguridad ausentes
8. Endpoint de debug que expone la DB
═══════════════════════════════════════════════════════
```

### Probar versión SEGURA

```bash
npm run test:secure
```

**Salida esperada:**

```
═══════════════════════════════════════════════════════
       PRUEBAS - VERSIÓN SEGURA
═══════════════════════════════════════════════════════

[TEST 1] Intentar registro con contraseña DÉBIL
✓ PROTEGIDO: Contraseña débil rechazada

[TEST 2] Registro con contraseña FUERTE
✓ PROTEGIDO: Usuario creado con contraseña fuerte

[TEST 3] Login y verificar token de sesión
✓ PROTEGIDO: Token criptográficamente seguro

[TEST 4] Verificar flags de seguridad en cookie
✓ PROTEGIDO: Cookie con flags de seguridad:
   HttpOnly: SÍ
   SameSite: SÍ

[TEST 5] Obtener perfil del usuario
✓ PROTEGIDO: Datos sensibles ENMASCARADOS:
   SSN: ***-**-6789
   Tarjeta: **** **** **** 9010

[TEST 6] Intentar acceder sin autenticación
✓ PROTEGIDO: Acceso denegado

[TEST 7] Verificar headers de seguridad
✓ PROTEGIDO: Headers de seguridad presentes

[TEST 8] Probar rate limiting
✓ BLOQUEADO en intento 6

[TEST 9] Verificar endpoint /api/debug/database
✓ PROTEGIDO: Endpoint de debug no existe

[TEST 10] Listar usuarios
✓ PROTEGIDO: Lista SIN datos sensibles

═══════════════════════════════════════════════════════
RESUMEN DE PROTECCIONES VERIFICADAS:
✓ Validación de contraseñas fuertes
✓ Hashing con bcrypt (12 rounds)
✓ Cifrado de datos sensibles (AES-256-GCM)
✓ Tokens criptográficamente seguros
✓ Cookies con flags de seguridad
✓ Enmascaramiento de datos sensibles
✓ Rate limiting
✓ Headers de seguridad (Helmet)
✓ Autenticación requerida
✓ Sin exposición de datos
═══════════════════════════════════════════════════════
```

### Pruebas manuales con cURL

#### Versión VULNERABLE

```bash
# Registro con contraseña débil (ACEPTADO)
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test\",\"password\":\"123\",\"email\":\"test@example.com\",\"ssn\":\"123-45-6789\"}"

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test\",\"password\":\"123\"}"

# Ver base de datos completa
curl http://localhost:3000/api/debug/database
```

#### Versión SEGURA

```bash
# Registro con contraseña débil (RECHAZADO)
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test\",\"password\":\"123\",\"email\":\"test@example.com\"}"

# Registro con contraseña fuerte
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test\",\"password\":\"MySecureP@ssw0rd2024!\",\"email\":\"test@example.com\",\"ssn\":\"123-45-6789\"}"

# Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test\",\"password\":\"MySecureP@ssw0rd2024!\"}" \
  -c cookies.txt

# Ver perfil (datos enmascarados)
curl http://localhost:3001/api/auth/profile \
  -b cookies.txt
```

---

## Arquitectura MVC

Este proyecto implementa el patrón **Modelo-Vista-Controlador (MVC)**:

### Modelo (Model)

- **Ubicación**: `models/User.js`
- **Responsabilidad**: Lógica de negocio y acceso a datos
- **Funciones**:
  - Validación de datos
  - Operaciones CRUD en la base de datos
  - Hashing/cifrado de datos sensibles
  - Gestión de sesiones

### Vista (View)

- **En este proyecto**: API REST
- **Formato**: JSON
- **Responsabilidad**: Presentación de datos al cliente

### Controlador (Controller)

- **Ubicación**: `controllers/authController.js`
- **Responsabilidad**: Coordinar Modelo y Vista
- **Funciones**:
  - Recibir requests HTTP
  - Validar entrada del usuario
  - Llamar métodos del modelo
  - Retornar respuestas JSON

### Rutas (Routes)

- **Ubicación**: `routes/authRoutes.js`
- **Responsabilidad**: Mapear URLs a controladores
- **Incluye**: Middlewares (rate limiting, autenticación)

### Configuración (Config)

- **Ubicación**: `config/database.js`
- **Responsabilidad**: Configuración de servicios
- **Incluye**: Conexión a BD, helpers de cifrado

```
Request → Route → Controller → Model → Database
                      ↓
                  Response
```

---

## Lecciones Aprendidas

### 1. Nunca confíes en la entrada del usuario

- Valida **todo** en el servidor
- Sanitiza datos antes de procesarlos
- Usa bibliotecas como `validator`

### 2. Usa algoritmos criptográficos modernos

- **Para contraseñas**: bcrypt, Argon2, scrypt
- **Para cifrado**: AES-256-GCM, ChaCha20-Poly1305
- **Evita**: MD5, SHA1, DES, RC4

### 3. Separa las claves del código

- Usa variables de entorno (`.env`)
- Usa gestores de secretos en producción
- Nunca hagas commit de `.env`

### 4. Implementa defensa en profundidad

- Cifrado en tránsito (HTTPS)
- Cifrado en reposo (AES-256)
- Rate limiting
- Headers de seguridad
- Auditoría

### 5. Minimiza la exposición de datos

- Solo retorna lo necesario
- Enmascara datos sensibles
- Requiere reautenticación para datos críticos

### 6. Mantén logs seguros

- NO registres contraseñas
- NO registres datos sensibles
- Usa niveles de log apropiados
- Implementa auditoría separada

### 7. Diseña para el fallo

- Asume que la BD puede ser comprometida
- Cifra datos sensibles
- Usa hashing seguro
- Implementa expiración de sesiones

---

## Próximos Pasos

Para mejorar aún más la seguridad:

1. **Implementar HTTPS**:

   ```bash
   # Generar certificado SSL autofirmado
   openssl req -nodes -new -x509 -keyout server.key -out server.cert
   ```

2. **Agregar autenticación de dos factores (2FA)**:

   - TOTP (Google Authenticator)
   - SMS
   - Email

3. **Implementar gestión de secretos**:

   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault

4. **Agregar más validaciones**:

   - Verificación de email
   - CAPTCHA
   - Análisis de comportamiento

5. **Monitoreo y alertas**:
   - Detectar patrones de ataque
   - Alertas de múltiples intentos fallidos
   - Dashboard de seguridad

---

## Recursos Adicionales

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [Documentación de bcrypt](https://github.com/kelektiv/node.bcrypt.js)
- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Helmet.js](https://helmetjs.github.io/)

---

## Autor

**Proyecto educativo**
Materia: Seguridad de la Información en Computación
Tema: A04:2025 - Cryptographic Failures

---

## Licencia

Este proyecto es material educativo y puede ser utilizado libremente con fines académicos.

⚠️ **ADVERTENCIA**: La versión vulnerable es solo para propósitos educativos. NUNCA uses código similar en producción.
