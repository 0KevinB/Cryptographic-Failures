// API Base URL
const API_BASE = '/api/auth';

// Estado de la aplicación
let currentSession = {
    authenticated: false,
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

    if (currentSession.authenticated) {
        sessionInfo.classList.remove('hidden');
        currentUser.textContent = currentSession.username || 'Usuario';
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

// Validación de fortaleza de contraseña
function checkPasswordStrength(password) {
    const strengthIndicator = document.getElementById('passwordStrength');

    if (!password) {
        strengthIndicator.classList.remove('show');
        return;
    }

    strengthIndicator.classList.add('show');

    let strength = 0;

    // Criterios
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*]/.test(password)) strength++;

    // Actualizar barra
    strengthIndicator.innerHTML = '';
    const bar = document.createElement('div');
    bar.className = 'password-strength-bar';

    if (strength < 3) {
        bar.classList.add('strength-weak');
        bar.textContent = 'Débil';
    } else if (strength < 5) {
        bar.classList.add('strength-medium');
        bar.textContent = 'Media';
    } else {
        bar.classList.add('strength-strong');
        bar.textContent = 'Fuerte';
    }

    strengthIndicator.appendChild(bar);
}

// Event listener para contraseña
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('regPassword');
    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            checkPasswordStrength(e.target.value);
        });
    }

    updateSessionInfo();

    console.log('%c✓ VERSIÓN SEGURA ✓', 'color: #28a745; font-size: 20px; font-weight: bold;');
    console.log('%cEsta aplicación implementa controles de seguridad apropiados', 'color: #17a2b8; font-size: 14px;');
    console.log('%cTodas las medidas de protección están activas', 'color: #28a745; font-size: 14px;');
});

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
            credentials: 'include',
            body: JSON.stringify(userData)
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            alert('✓ Usuario registrado exitosamente!\n\n🔒 Seguridad:\n- Contraseña hasheada con bcrypt\n- Datos sensibles cifrados con AES-256-GCM\n- Todos los campos validados');
            // Limpiar formulario
            event.target.reset();
            document.getElementById('passwordStrength').classList.remove('show');
        } else {
            alert('Error al registrar:\n' + data.message);
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
            credentials: 'include',
            body: JSON.stringify(credentials)
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.status === 429) {
            // Rate limit alcanzado
            const rateLimitInfo = document.getElementById('rateLimitInfo');
            const rateLimitMessage = document.getElementById('rateLimitMessage');
            rateLimitInfo.classList.remove('hidden');
            rateLimitMessage.textContent = data.message;
            alert('🔒 Rate Limit Activado\n\n' + data.message);
            return;
        }

        if (response.status === 423) {
            // Cuenta bloqueada
            alert('🔒 Cuenta Bloqueada\n\n' + data.message);
            return;
        }

        if (response.ok) {
            currentSession.authenticated = true;
            currentSession.username = data.user.username;
            updateSessionInfo();

            alert('✓ Login exitoso!\n\n🔒 Seguridad:\n- Token criptográficamente seguro (256 bits)\n- Cookie con flags HTTPOnly, Secure, SameSite\n- Sesión expira en 24 horas');

            // Limpiar formulario
            event.target.reset();

            // Ocultar mensaje de rate limit si estaba visible
            document.getElementById('rateLimitInfo').classList.add('hidden');
        } else {
            alert('Error al iniciar sesión:\n' + data.message);
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
            credentials: 'include'
        });

        const data = await response.json();
        showResponse(data, response.status);

        currentSession.authenticated = false;
        currentSession.username = null;
        updateSessionInfo();

        alert('✓ Sesión cerrada correctamente');
    } catch (error) {
        alert('Error al cerrar sesión: ' + error.message);
    }
}

// Obtener perfil
async function getProfile() {
    if (!currentSession.authenticated) {
        alert('🔒 Debes iniciar sesión primero');
        showTab('login');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/profile`, {
            method: 'GET',
            credentials: 'include'
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.ok) {
            displayProfile(data.user);
        } else {
            if (response.status === 401) {
                currentSession.authenticated = false;
                updateSessionInfo();
                alert('Sesión expirada. Por favor inicia sesión nuevamente.');
                showTab('login');
            } else {
                alert('Error al obtener perfil: ' + data.message);
            }
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Mostrar perfil en formato legible
function displayProfile(user) {
    const profileResult = document.getElementById('profileResult');

    profileResult.innerHTML = `
        <h4>🔒 Información del Usuario (Datos Enmascarados)</h4>
        <table>
            <tr>
                <th>Campo</th>
                <th>Valor</th>
                <th>Estado</th>
            </tr>
            <tr>
                <td>ID</td>
                <td>${user.id}</td>
                <td><span class="badge badge-success">Público</span></td>
            </tr>
            <tr>
                <td>Username</td>
                <td>${user.username}</td>
                <td><span class="badge badge-success">Público</span></td>
            </tr>
            <tr>
                <td>Email</td>
                <td>${user.email}</td>
                <td><span class="badge badge-success">Público</span></td>
            </tr>
            <tr>
                <td>SSN</td>
                <td class="masked-data">${user.ssn || 'No especificado'}</td>
                <td><span class="badge badge-warning">Enmascarado</span></td>
            </tr>
            <tr>
                <td>Tarjeta de Crédito</td>
                <td class="masked-data">${user.credit_card || 'No especificado'}</td>
                <td><span class="badge badge-warning">Enmascarado</span></td>
            </tr>
            <tr>
                <td>Información Médica</td>
                <td class="masked-data">${user.medical_info || 'No especificado'}</td>
                <td><span class="badge badge-warning">Enmascarado</span></td>
            </tr>
            <tr>
                <td>Creado</td>
                <td>${user.created_at ? new Date(user.created_at).toLocaleString() : 'N/A'}</td>
                <td><span class="badge badge-success">Público</span></td>
            </tr>
            <tr>
                <td>Último login</td>
                <td>${user.last_login ? new Date(user.last_login).toLocaleString() : 'N/A'}</td>
                <td><span class="badge badge-success">Público</span></td>
            </tr>
        </table>
        <div class="info-box secure" style="margin-top: 20px;">
            <h4>✓ PROTECCIÓN IMPLEMENTADA</h4>
            <p>Los datos sensibles se muestran enmascarados por defecto.</p>
            <p>Para acceder a los datos completos, ve a la pestaña "Datos Sensibles" y confirma tu contraseña.</p>
        </div>
    `;
}

// Obtener datos sensibles completos (requiere reautenticación)
async function getSensitiveData(event) {
    event.preventDefault();

    if (!currentSession.authenticated) {
        alert('🔒 Debes iniciar sesión primero');
        showTab('login');
        return;
    }

    const password = document.getElementById('sensitivePassword').value;

    try {
        const response = await fetch(`${API_BASE}/sensitive-data`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ password })
        });

        const data = await response.json();
        showResponse(data, response.status);

        if (response.status === 429) {
            alert('🔒 Rate Limit Activado\n\nDemasiados intentos de acceso a datos sensibles.');
            return;
        }

        if (response.ok) {
            displaySensitiveData(data.sensitiveData);
            alert('✓ Acceso concedido\n\n⚠️ Este acceso ha sido registrado en el log de auditoría.');
            document.getElementById('sensitivePassword').value = '';
        } else {
            alert('❌ Acceso denegado\n\n' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Mostrar datos sensibles completos
function displaySensitiveData(data) {
    const sensitiveResult = document.getElementById('sensitiveResult');

    sensitiveResult.innerHTML = `
        <h4>🔐 Datos Sensibles Completos</h4>
        <div class="info-box warning">
            <p><strong>⚠️ Información Sensible:</strong> Estos datos han sido descifrados desde AES-256-GCM.</p>
            <p>Este acceso ha sido registrado en el log de auditoría.</p>
        </div>
        <table>
            <tr>
                <th>Campo</th>
                <th>Valor Descifrado</th>
            </tr>
            <tr>
                <td>SSN</td>
                <td class="sensitive-data">${data.ssn || 'No especificado'}</td>
            </tr>
            <tr>
                <td>Tarjeta de Crédito</td>
                <td class="sensitive-data">${data.credit_card || 'No especificado'}</td>
            </tr>
            <tr>
                <td>Información Médica</td>
                <td class="sensitive-data">${data.medical_info || 'No especificado'}</td>
            </tr>
        </table>
    `;
}

// Obtener lista de usuarios
async function getUsers() {
    if (!currentSession.authenticated) {
        alert('🔒 Debes iniciar sesión primero');
        showTab('login');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/users`, {
            method: 'GET',
            credentials: 'include'
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

    let html = '<h4>✓ Lista de Usuarios (Solo Información Pública)</h4>';
    html += '<table>';
    html += `
        <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Fecha de Creación</th>
        </tr>
    `;

    users.forEach(user => {
        html += `
            <tr>
                <td>${user.id}</td>
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
            </tr>
        `;
    });

    html += '</table>';

    html += '<div class="info-box secure" style="margin-top: 20px;">';
    html += '<h4>✓ PROTECCIÓN DE PRIVACIDAD</h4>';
    html += '<p>Solo se muestran datos públicos. Los siguientes campos NO están expuestos:</p>';
    html += '<ul>';
    html += '<li>Hashes de contraseñas</li>';
    html += '<li>SSN</li>';
    html += '<li>Tarjetas de crédito</li>';
    html += '<li>Información médica</li>';
    html += '<li>Tokens de sesión</li>';
    html += '</ul>';
    html += '</div>';

    usersResult.innerHTML = html;
}
