# 🎨 Guía de Interfaces Web

## Interfaz Gráfica Interactiva

Ambas versiones (vulnerable y segura) ahora incluyen interfaces web completas con HTML y CSS para interactuar visualmente con todos los endpoints de la API.

---

## 🚀 Cómo Usar

### 1. Iniciar los Servidores

**Terminal 1 - Versión Vulnerable:**
```bash
npm run start:vulnerable
```

**Terminal 2 - Versión Segura:**
```bash
npm run start:secure
```

### 2. Acceder a las Interfaces

- **Versión VULNERABLE**: http://localhost:3000
- **Versión SEGURA**: http://localhost:3001

---

## 🔴 Interfaz VULNERABLE (Puerto 3000)

### Características Visuales

- **Tema**: Rojo/Naranja con advertencias constantes
- **Banner**: Animado con iconos de advertencia ⚠️
- **Colores**: Esquema oscuro con énfasis en vulnerabilidades

### Pestañas Disponibles

#### 1️⃣ **Registro**
- Permite crear usuarios con contraseñas débiles (ej: "123")
- Acepta cualquier longitud de contraseña
- Muestra advertencias sobre almacenamiento en texto plano
- Campos sensibles (SSN, tarjeta, info médica) sin validación

**Ejemplo de Prueba:**
```
Username: testuser
Password: 123          ← Contraseña débil aceptada
Email: test@example.com
SSN: 123-45-6789      ← Se guarda en texto plano
Tarjeta: 4532-1234-5678-9010  ← Se guarda en texto plano
```

#### 2️⃣ **Login**
- Sin rate limiting
- Permite intentos ilimitados
- Botón especial: "Simular Ataque de Fuerza Bruta"
  - Hace 10 intentos consecutivos
  - Demuestra la falta de protección

**Prueba:**
1. Ingresa un usuario existente
2. Intenta con contraseñas incorrectas múltiples veces
3. ⚠️ No hay límite de intentos

#### 3️⃣ **Perfil**
- Muestra TODOS los datos sin enmascarar
- SSN completo visible
- Tarjeta de crédito completa visible
- Información médica sin restricciones
- Token de sesión predecible mostrado

#### 4️⃣ **Usuarios**
- Lista TODOS los usuarios registrados
- Expone:
  - Hashes MD5 de contraseñas
  - SSN de todos los usuarios
  - Tarjetas de crédito de todos
  - Información médica de todos
- Sin autenticación requerida

#### 5️⃣ **🔍 Debug DB**
- Endpoint crítico de vulnerabilidad
- Muestra la base de datos COMPLETA
- Sin autenticación
- Formato RAW con todos los campos
- Código coloreado para resaltar vulnerabilidades

---

## 🟢 Interfaz SEGURA (Puerto 3001)

### Características Visuales

- **Tema**: Verde/Azul con indicadores de protección
- **Banner**: Animado con candados 🔒 y checkmarks ✓
- **Colores**: Esquema oscuro con énfasis en seguridad

### Pestañas Disponibles

#### 1️⃣ **Registro**
- Validación de contraseñas fuertes requerida
- Indicador visual de fortaleza de contraseña
- Mínimo 12 caracteres
- Requiere mayúsculas, minúsculas, números y caracteres especiales
- Mensajes claros sobre cifrado AES-256-GCM

**Ejemplo de Prueba:**
```
Username: secureuser
Password: MySecureP@ssw0rd2024!  ← Contraseña fuerte requerida
Email: secure@example.com
SSN: 123-45-6789      ← Se cifrará con AES-256-GCM
```

**Indicador de Fortaleza:**
- 🔴 Rojo = Débil
- 🟡 Amarillo = Media
- 🟢 Verde = Fuerte

#### 2️⃣ **Login**
- Rate limiting activo (5 intentos / 15 min)
- Bloqueo de cuenta tras 5 intentos fallidos
- Mensaje informativo sobre protecciones
- Cookie con flags de seguridad (HTTPOnly, Secure, SameSite)

**Prueba de Rate Limiting:**
1. Intenta login con contraseña incorrecta 6 veces
2. Al 6to intento verás: "Demasiados intentos. Intente más tarde."

#### 3️⃣ **Perfil**
- Datos sensibles **ENMASCARADOS**
- SSN: `***-**-6789` (solo últimos 4 dígitos)
- Tarjeta: `**** **** **** 9010` (solo últimos 4 dígitos)
- Info médica: `[Información médica disponible]`
- Badges indicando estado:
  - 🟢 Público
  - 🟡 Enmascarado

#### 4️⃣ **Datos Sensibles**
- Requiere **reautenticación** con contraseña
- Rate limiting especial (3 intentos / 15 min)
- Log de auditoría automático
- Advertencia clara sobre acceso registrado

**Flujo:**
1. Ingresa tu contraseña actual
2. Confirma tu identidad
3. Accede a datos completos descifrados
4. Este acceso queda registrado en auditoría

#### 5️⃣ **Usuarios**
- Solo muestra información pública
- Campos expuestos:
  - ID
  - Username
  - Email
  - Fecha de creación
- **NO expone:**
  - Contraseñas (ni hashes)
  - SSN
  - Tarjetas
  - Info médica

---

## 🎯 Comparación Visual

| Aspecto | Vulnerable | Segura |
|---------|-----------|--------|
| **Color Principal** | 🔴 Rojo | 🟢 Verde |
| **Tema** | Advertencias | Protecciones |
| **Contraseñas** | Cualquier longitud | Min 12 chars + complejidad |
| **Indicador de Fortaleza** | ❌ No | ✅ Sí |
| **Rate Limiting** | ❌ No | ✅ Sí (visible en UI) |
| **Datos Sensibles** | Expuestos | Enmascarados |
| **Token Visible** | ✅ Sí (predecible) | ❌ No (oculto) |
| **Debug Endpoint** | ✅ Sí (peligroso) | ❌ No existe |
| **Reautenticación** | ❌ No | ✅ Para datos sensibles |

---

## 📋 Flujo de Prueba Recomendado

### Versión VULNERABLE

1. **Abre**: http://localhost:3000
2. **Registra** un usuario con contraseña "123"
3. **Login** con ese usuario
4. Ve a **Perfil** y observa todos los datos expuestos
5. Ve a **Usuarios** y ve datos de todos
6. Ve a **Debug DB** y observa la base de datos completa
7. Intenta **Simular Ataque de Fuerza Bruta** desde el tab Login

### Versión SEGURA

1. **Abre**: http://localhost:3001
2. **Intenta registrar** con contraseña "123" → Rechazado
3. **Registra** con `MySecureP@ssw0rd2024!`
4. **Login** con ese usuario
5. Ve a **Perfil** → Datos enmascarados
6. Ve a **Datos Sensibles** → Requiere contraseña
7. Ingresa tu contraseña para ver datos completos
8. Ve a **Usuarios** → Solo info pública
9. Intenta login incorrecto 6 veces → Rate limited

---

## 🎨 Características de UI

### Ambas Versiones

- ✅ Diseño responsive (funciona en móviles)
- ✅ Tabs para navegación
- ✅ Área de respuestas del servidor
- ✅ Formato JSON con syntax highlighting
- ✅ Scroll suave entre secciones
- ✅ Alertas informativas
- ✅ Tablas formateadas para datos

### Vulnerable (Características Especiales)

- ⚠️ Animaciones de pulso en advertencias
- 🔴 Botón de ataque de fuerza bruta animado
- 📊 Vista de base de datos RAW con formato código
- 🎯 Énfasis visual en datos expuestos

### Segura (Características Especiales)

- 🔒 Animación de brillo en candados
- 💪 Indicador de fortaleza de contraseña en tiempo real
- 🏷️ Badges de estado (Público/Enmascarado)
- 🔐 Modal de reautenticación para datos sensibles
- ⏱️ Indicadores de rate limiting

---

## 🖥️ Atajos de Teclado

- **Tab**: Navegar entre campos de formulario
- **Enter**: Enviar formulario activo
- **Esc**: (futuro) Cerrar modales

---

## 📱 Responsive Design

Las interfaces funcionan en:
- 💻 Desktop (1920x1080+)
- 💻 Laptop (1366x768)
- 📱 Tablet (768x1024)
- 📱 Mobile (375x667)

En pantallas pequeñas:
- Los tabs se vuelven verticales
- Las tablas son scrolleables
- Los formularios se adaptan al ancho

---

## 🎭 Demostraciones Sugeridas

### Demo 1: Contraseñas Débiles vs Fuertes

1. Vulnerable: Registra con "123" ✅ Aceptado
2. Segura: Intenta "123" ❌ Rechazado
3. Segura: Usa "MySecureP@ss2024!" ✅ Aceptado

### Demo 2: Exposición de Datos

1. Vulnerable: Ve perfil → Todo visible
2. Segura: Ve perfil → Datos enmascarados
3. Segura: Usa "Datos Sensibles" con password

### Demo 3: Rate Limiting

1. Vulnerable: 20 intentos de login → Todos permitidos
2. Segura: 6 intentos de login → Bloqueado al 6to

### Demo 4: Acceso a Lista de Usuarios

1. Vulnerable: Ve "Usuarios" → Hashes MD5, SSN, tarjetas
2. Segura: Ve "Usuarios" → Solo info pública

### Demo 5: Base de Datos

1. Vulnerable: "Debug DB" → BD completa en texto plano
2. Segura: No existe ese endpoint → 404

---

## 🐛 Troubleshooting

### Problema: "Cannot GET /"
**Solución**: Asegúrate que la carpeta `public` existe en cada versión

### Problema: CSS no se carga
**Solución**: Verifica que `styles.css` está en `public/`

### Problema: JavaScript no funciona
**Solución**: Abre la consola del navegador (F12) y verifica errores

### Problema: No se puede conectar al servidor
**Solución**:
- Verifica que el servidor está corriendo
- Vulnerable: http://localhost:3000
- Segura: http://localhost:3001

### Problema: Rate limit no aparece
**Solución**: En la versión segura, necesitas hacer 6 intentos fallidos

### Problema: Datos sensibles no se descifran
**Solución**: Verifica que el `.env` tiene `ENCRYPTION_KEY` configurada

---

## 💡 Consejos de Uso

1. **Abre ambas interfaces en tabs diferentes** para comparar en tiempo real
2. **Usa la consola del navegador** (F12) para ver logs adicionales
3. **Verifica el "Área de Respuestas"** para ver JSON del servidor
4. **Prueba en diferentes navegadores** para ver comportamiento de cookies
5. **Usa el modo incógnito** para probar sesiones limpias

---

## 🎓 Propósito Educativo

Estas interfaces están diseñadas para:

✅ Demostrar visualmente las diferencias entre código vulnerable y seguro
✅ Facilitar la comprensión de conceptos de seguridad
✅ Permitir pruebas prácticas sin necesidad de curl o Postman
✅ Mostrar feedback visual inmediato de controles de seguridad
✅ Hacer la presentación más interactiva y profesional

---

## 📸 Screenshots

### Vulnerable
```
┌─────────────────────────────────────────┐
│  ⚠️  VERSIÓN VULNERABLE  ⚠️             │
│  [Registro] [Login] [Perfil] [Debug]   │
│                                         │
│  Password: [123] ← ACEPTADO!            │
│  ⚠️ Se almacena en texto plano          │
└─────────────────────────────────────────┘
```

### Segura
```
┌─────────────────────────────────────────┐
│  🔒 VERSIÓN SEGURA ✓                    │
│  [Registro] [Login] [Perfil] [Sensible]│
│                                         │
│  Password: [MySecureP@ss2024!]          │
│  ████████████ FUERTE ✓                  │
└─────────────────────────────────────────┘
```

---

## 🚀 Próximos Pasos

Después de explorar las interfaces:

1. ✅ Compara las respuestas del servidor en ambas versiones
2. ✅ Revisa el código fuente de las interfaces (`public/script.js`)
3. ✅ Modifica los estilos en `public/styles.css`
4. ✅ Agrega nuevas funcionalidades si lo deseas
5. ✅ Presenta tu proyecto con confianza

---

**¡Disfruta explorando las diferencias entre código vulnerable y seguro de forma visual e interactiva!** 🎉
