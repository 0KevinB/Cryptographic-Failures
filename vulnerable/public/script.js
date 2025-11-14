// API Base URL
const API_BASE = '/api/auth';

// Estado de la aplicación
let currentSession = {
    token: null,
    username: null
};

// Función para mostrar respuestas del servidor
function showResponse(data, statusCode = 200) {
    const responseArea = document.getElementById('responseArea');
    const responseContent = document.getElementById('responseContent');

    responseArea.classList.remove('hidden');
    responseContent.textContent = JSON.stringify(data, null, 2);

    // Scroll suave hacia la respuesta
    responseArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Función para mostrar información de sesión
function updateSessionInfo() {
    const sessionInfo = document.getElementById('sessionInfo');
    const currentUser = document.getElementById('currentUser');
    const currentToken = document.getElementById('currentToken');

    if (currentSession.token) {
        sessionInfo.classList.remove('hidden');
        currentUser.textContent = currentSession.username || 'Desconocido';
        currentToken.textContent = currentSession.token;
    } else {
        sessionInfo.classList.add('hidden');
    }
}

// Función para cambiar de tab
function showTab(tabName, event) {
    // Ocultar todos los tabs
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));

    // Desactivar todos los botones
    const buttons = document.querySelectorAll('.tab-button');
    buttons.forEach(btn => btn.classList.remove('active'));

    // Activar el tab seleccionado
    document.getElementById(tabName + 'Tab').classList.add('active');
    if (event && event.target) {
        event.target.classList.add('active');
    }
}

// Registro de usuario
async function register(event) {
    event.preventDefault();

    const userData = {
        username: document.getElementById('regUsername').value,
        password: document.getElementById('regPassword').value,
        email: document.getElementById('regEmail').value,
        ssn: document.getElementById('regSSN').value,
        credit_card: document.getElementById('regCard').value,
        medical_info: document.getElementById('regMedical').value
    };

    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            alert('✓ Usuario registrado exitosamente!\n\n⚠️ NOTA: Los datos sensibles se almacenaron en TEXTO PLANO en la base de datos.');
            // Limpiar formulario
            event.target.reset();
        } else {
            alert('Error al registrar: ' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Login
async function login(event) {
    event.preventDefault();

    const credentials = {
        username: document.getElementById('loginUsername').value,
        password: document.getElementById('loginPassword').value
    };

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            currentSession.token = data.sessionToken;
            currentSession.username = data.user.username;
            updateSessionInfo();

            alert('✓ Login exitoso!\n\n⚠️ NOTA: El token de sesión es predecible (MD5 del timestamp).');

            // Limpiar formulario
            event.target.reset();
        } else {
            alert('Error al iniciar sesión: ' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Cerrar sesión
async function logout() {
    try {
        const response = await fetch(`${API_BASE}/logout`, {
            method: 'POST',
            headers: {
                'X-Session-Token': currentSession.token
            }
        });

        const data = await response.json();
        showResponse(data, response.status);

        currentSession.token = null;
        currentSession.username = null;
        updateSessionInfo();

        alert('Sesión cerrada');
    } catch (error) {
        alert('Error al cerrar sesión: ' + error.message);
    }
}

// Obtener perfil
async function getProfile() {
    if (!currentSession.token) {
        alert('⚠️ Debes iniciar sesión primero');
        showTab('login');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/profile`, {
            method: 'GET',
            headers: {
                'X-Session-Token': currentSession.token
            }
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            displayProfile(data.user);
        } else {
            alert('Error al obtener perfil: ' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Mostrar perfil en formato legible
function displayProfile(user) {
    const profileResult = document.getElementById('profileResult');

    profileResult.innerHTML = `
        <h4>⚠️ Información del Usuario (TODOS LOS DATOS EXPUESTOS)</h4>
        <table>
            <tr>
                <th>Campo</th>
                <th>Valor</th>
                <th>Estado</th>
            </tr>
            <tr>
                <td>ID</td>
                <td>${user.id}</td>
                <td>Público</td>
            </tr>
            <tr>
                <td>Username</td>
                <td>${user.username}</td>
                <td>Público</td>
            </tr>
            <tr>
                <td>Email</td>
                <td>${user.email}</td>
                <td>Público</td>
            </tr>
            <tr>
                <td>SSN</td>
                <td class="sensitive-data">${user.ssn || 'No especificado'}</td>
                <td class="sensitive-data">⚠️ EXPUESTO</td>
            </tr>
            <tr>
                <td>Tarjeta de Crédito</td>
                <td class="sensitive-data">${user.credit_card || 'No especificado'}</td>
                <td class="sensitive-data">⚠️ EXPUESTO</td>
            </tr>
            <tr>
                <td>Información Médica</td>
                <td class="sensitive-data">${user.medical_info || 'No especificado'}</td>
                <td class="sensitive-data">⚠️ EXPUESTO</td>
            </tr>
        </table>
        <div class="info-box vulnerable" style="margin-top: 20px;">
            <h4>⚠️ VULNERABILIDAD</h4>
            <p>Todos los datos sensibles están expuestos sin ningún tipo de enmascaramiento o cifrado en la respuesta.</p>
        </div>
    `;
}

// Obtener lista de usuarios
async function getUsers() {
    try {
        const response = await fetch(`${API_BASE}/users`, {
            method: 'GET'
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            displayUsers(data.users);
        } else {
            alert('Error al obtener usuarios: ' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Mostrar lista de usuarios
function displayUsers(users) {
    const usersResult = document.getElementById('usersResult');

    if (!users || users.length === 0) {
        usersResult.innerHTML = '<p>No hay usuarios registrados</p>';
        return;
    }

    let html = '<h4>⚠️ TODOS los usuarios con TODOS sus datos</h4>';
    html += '<table>';
    html += `
        <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Password Hash (MD5)</th>
            <th>Email</th>
            <th>SSN</th>
            <th>Tarjeta</th>
            <th>Info Médica</th>
        </tr>
    `;

    users.forEach(user => {
        html += `
            <tr>
                <td>${user.id}</td>
                <td>${user.username}</td>
                <td class="sensitive-data" style="font-size: 0.8rem;">${user.password}</td>
                <td>${user.email}</td>
                <td class="sensitive-data">${user.ssn || '-'}</td>
                <td class="sensitive-data">${user.credit_card || '-'}</td>
                <td class="sensitive-data">${user.medical_info || '-'}</td>
            </tr>
        `;
    });

    html += '</table>';
    usersResult.innerHTML = html;
}

// Ver base de datos completa (endpoint de debug)
async function getDatabase() {
    try {
        const response = await fetch('/api/debug/database', {
            method: 'GET'
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            displayDatabase(data);
        } else {
            alert('Error al obtener base de datos: ' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Mostrar base de datos
function displayDatabase(data) {
    const debugResult = document.getElementById('debugResult');

    const users = data.users;

    if (!users || users.length === 0) {
        debugResult.innerHTML = '<p>La base de datos está vacía</p>';
        return;
    }

    let html = '<div class="info-box vulnerable">';
    html += '<h4>🔍 BASE DE DATOS RAW</h4>';
    html += '<p>Este es el contenido EXACTO de la base de datos SQLite:</p>';
    html += '</div>';

    html += '<div style="background: #000; padding: 15px; border-radius: 5px; margin-top: 15px;">';
    html += '<pre style="margin: 0; color: #0f0; font-family: monospace; font-size: 0.85rem;">';

    users.forEach((user, index) => {
        html += `\n// Usuario ${index + 1}\n`;
        html += `{\n`;
        html += `  id: ${user.id},\n`;
        html += `  username: "${user.username}",\n`;
        html += `  password: "${user.password}",    // ⚠️ MD5 Hash\n`;
        html += `  email: "${user.email}",\n`;
        html += `  ssn: "${user.ssn || 'NULL'}",              // ⚠️ TEXTO PLANO\n`;
        html += `  credit_card: "${user.credit_card || 'NULL'}",  // ⚠️ TEXTO PLANO\n`;
        html += `  medical_info: "${user.medical_info || 'NULL'}", // ⚠️ TEXTO PLANO\n`;
        html += `  created_at: "${user.created_at}"\n`;
        html += `}\n`;
    });

    html += '</pre></div>';

    html += '<div class="info-box vulnerable" style="margin-top: 20px;">';
    html += '<h4>⚠️ ANÁLISIS DE VULNERABILIDADES</h4>';
    html += '<ul>';
    html += '<li><strong>Contraseñas con MD5:</strong> Se pueden crackear en segundos usando rainbow tables</li>';
    html += '<li><strong>Datos en texto plano:</strong> SSN, tarjetas de crédito e información médica completamente expuestos</li>';
    html += '<li><strong>Sin cifrado:</strong> Cualquiera con acceso a la base de datos puede leer todo</li>';
    html += '<li><strong>Sin control de acceso:</strong> Este endpoint no requiere autenticación</li>';
    html += '</ul>';
    html += '</div>';

    debugResult.innerHTML = html;
}

// Simulación de ataque de fuerza bruta
async function bruteForceTest() {
    const username = document.getElementById('loginUsername').value;

    if (!username) {
        alert('Ingresa un username primero');
        return;
    }

    if (!confirm('Esto intentará hacer login 10 veces con contraseñas incorrectas para demostrar la ausencia de rate limiting.\n\n¿Continuar?')) {
        return;
    }

    const passwords = ['123', 'password', 'admin', 'test', '1234', '12345', 'qwerty', 'abc123', 'password123', 'admin123'];
    let attempts = 0;
    let blocked = false;

    alert('Iniciando ataque de fuerza bruta...');

    for (const password of passwords) {
        attempts++;

        try {
            const response = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            console.log(`Intento ${attempts}: ${password} - Status: ${response.status}`);

            if (response.status === 429) {
                blocked = true;
                alert(`✓ BLOQUEADO tras ${attempts} intentos (esto es bueno, pero NO ocurre en esta versión vulnerable)`);
                break;
            }

            // Pequeña pausa para no saturar
            await new Promise(resolve => setTimeout(resolve, 200));

        } catch (error) {
            console.error('Error en intento:', error);
        }
    }

    if (!blocked) {
        alert(`⚠️ VULNERABILIDAD CONFIRMADA\n\nSe completaron ${attempts} intentos de login sin ningún bloqueo.\n\nEn una aplicación real, esto permitiría probar miles de contraseñas hasta encontrar la correcta.`);
    }
}

// Inicialización
document.addEventListener('DOMContentLoaded', () => {
    console.log('%c⚠️ VERSIÓN VULNERABLE ⚠️', 'color: red; font-size: 20px; font-weight: bold;');
    console.log('%cEsta aplicación contiene vulnerabilidades intencionales para propósitos educativos', 'color: orange; font-size: 14px;');
    console.log('%cNUNCA uses código similar en producción', 'color: red; font-size: 14px; font-weight: bold;');

    updateSessionInfo();
});
