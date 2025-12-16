/**
 * =============================================================================
 * MÓDULO DE AUTENTICACIÓN - FRONTEND
 * =============================================================================
 *
 * Este módulo maneja toda la lógica de autenticación del cliente:
 * - Login con contraseña
 * - Login con biometría (WebAuthn)
 * - Registro de usuarios
 * - Registro de credenciales biométricas
 * - Gestión de tokens y sesiones
 * - Validación de formularios
 *
 * Compatible con:
 * - iOS (Face ID, Touch ID)
 * - Android (Huella, Face Unlock)
 * - Windows (Windows Hello)
 * - macOS (Touch ID)
 */

// =============================================================================
// CONFIGURACIÓN GLOBAL
// =============================================================================

const Auth = {
    // URL base de la API
    API_BASE: '/api',

    // Token CSRF actual
    csrfToken: null,

    // Datos del usuario actual
    currentUser: null,

    // Tipo de página actual
    pageType: null,

    // Indica si WebAuthn está soportado
    webAuthnSupported: false,

    // Temporizador de expiración de sesión
    sessionTimer: null,

    // ==========================================================================
    // INICIALIZACIÓN
    // ==========================================================================

    /**
     * Inicializa el módulo según el tipo de página
     * @param {string} type - Tipo de página: 'login', 'register', 'dashboard'
     */
    async init(type) {
        this.pageType = type;

        // Verificar soporte de WebAuthn
        await this.checkWebAuthnSupport();

        // Obtener token CSRF
        await this.getCsrfToken();

        // Inicializar según la página
        switch (type) {
            case 'login':
                this.initLoginPage();
                break;
            case 'register':
                this.initRegisterPage();
                break;
            case 'dashboard':
                await this.initDashboard();
                break;
        }

        // Configurar eventos globales
        this.setupGlobalEvents();
    },

    /**
     * Verifica si WebAuthn está soportado en el navegador
     */
    async checkWebAuthnSupport() {
        try {
            // Verificar si PublicKeyCredential está disponible
            if (window.PublicKeyCredential) {
                // Verificar si hay autenticador de plataforma disponible
                const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
                this.webAuthnSupported = available;

                console.log('WebAuthn soportado:', available);

                // Detectar tipo de dispositivo
                this.detectDeviceType();
            } else {
                this.webAuthnSupported = false;
                console.log('WebAuthn no soportado en este navegador');
            }
        } catch (error) {
            console.error('Error verificando WebAuthn:', error);
            this.webAuthnSupported = false;
        }
    },

    /**
     * Detecta el tipo de dispositivo para mostrar el texto apropiado
     */
    detectDeviceType() {
        const ua = navigator.userAgent.toLowerCase();
        let deviceHint = 'Biometría';

        if (ua.includes('iphone') || ua.includes('ipad')) {
            deviceHint = 'Face ID / Touch ID';
        } else if (ua.includes('android')) {
            deviceHint = 'Huella / Face Unlock';
        } else if (ua.includes('windows')) {
            deviceHint = 'Windows Hello';
        } else if (ua.includes('mac')) {
            deviceHint = 'Touch ID';
        }

        // Actualizar hint en la UI si existe
        const hintElement = document.getElementById('biometricHint');
        if (hintElement) {
            hintElement.textContent = deviceHint;
        }
    },

    /**
     * Obtiene el token CSRF del servidor
     */
    async getCsrfToken() {
        try {
            const response = await fetch(`${this.API_BASE}/csrf-token`, {
                credentials: 'include'
            });
            const data = await response.json();
            this.csrfToken = data.csrfToken;
        } catch (error) {
            console.error('Error obteniendo token CSRF:', error);
        }
    },

    // ==========================================================================
    // PÁGINA DE LOGIN
    // ==========================================================================

    /**
     * Inicializa la página de login
     */
    initLoginPage() {
        // Verificar si ya hay sesión activa
        this.checkExistingSession();

        // Configurar formulario de login
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Configurar botón de biometría
        const biometricBtn = document.getElementById('biometricBtn');
        if (biometricBtn && this.webAuthnSupported) {
            biometricBtn.style.display = 'flex';
            biometricBtn.addEventListener('click', () => this.handleBiometricLogin());
        }

        // Configurar toggle de contraseña
        this.setupPasswordToggle();
    },

    /**
     * Verifica si existe una sesión activa
     */
    async checkExistingSession() {
        try {
            const response = await fetch(`${this.API_BASE}/auth/me`, {
                credentials: 'include'
            });

            if (response.ok) {
                // Ya hay sesión, redirigir al dashboard
                window.location.href = '/dashboard';
            }
        } catch (error) {
            // No hay sesión, continuar en login
        }
    },

    /**
     * Maneja el envío del formulario de login
     */
    async handleLogin(event) {
        event.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const loginBtn = document.getElementById('loginBtn');
        const errorMessage = document.getElementById('errorMessage');

        // Validación básica
        if (!username || !password) {
            this.showError(errorMessage, 'Por favor, completa todos los campos');
            return;
        }

        // Mostrar loading
        this.setButtonLoading(loginBtn, true);
        this.hideError(errorMessage);

        try {
            const response = await fetch(`${this.API_BASE}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast('Login exitoso', 'success');
                // Pequeña pausa para mostrar el toast
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 500);
            } else {
                let errorMsg = data.error || 'Error al iniciar sesión';
                if (data.remainingAttempts !== undefined) {
                    errorMsg += `. Intentos restantes: ${data.remainingAttempts}`;
                }
                this.showError(errorMessage, errorMsg);
            }
        } catch (error) {
            console.error('Error en login:', error);
            this.showError(errorMessage, 'Error de conexión. Intenta de nuevo.');
        } finally {
            this.setButtonLoading(loginBtn, false);
        }
    },

    /**
     * Maneja el login con biometría
     */
    async handleBiometricLogin() {
        const username = document.getElementById('username').value.trim();
        const biometricBtn = document.getElementById('biometricBtn');
        const errorMessage = document.getElementById('errorMessage');

        if (!username) {
            this.showError(errorMessage, 'Ingresa tu nombre de usuario primero');
            document.getElementById('username').focus();
            return;
        }

        this.setButtonLoading(biometricBtn, true);
        this.hideError(errorMessage);

        try {
            // 1. Obtener opciones de autenticación del servidor
            const optionsResponse = await fetch(`${this.API_BASE}/auth/webauthn/login/options`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({ username }),
                credentials: 'include'
            });

            const optionsData = await optionsResponse.json();

            if (!optionsResponse.ok) {
                throw new Error(optionsData.error || 'Error obteniendo opciones');
            }

            // 2. Iniciar autenticación WebAuthn
            const { startAuthentication } = SimpleWebAuthnBrowser;
            const assertion = await startAuthentication(optionsData.options);

            // 3. Verificar con el servidor
            const verifyResponse = await fetch(`${this.API_BASE}/auth/webauthn/login/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({
                    response: assertion,
                    challengeId: optionsData.challengeId,
                    userId: optionsData.userId
                }),
                credentials: 'include'
            });

            const verifyData = await verifyResponse.json();

            if (verifyResponse.ok) {
                this.showToast('Autenticación biométrica exitosa', 'success');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 500);
            } else {
                throw new Error(verifyData.error || 'Error de verificación');
            }
        } catch (error) {
            console.error('Error en autenticación biométrica:', error);

            let errorMsg = 'Error en autenticación biométrica';
            if (error.name === 'NotAllowedError') {
                errorMsg = 'Autenticación cancelada o tiempo agotado';
            } else if (error.name === 'NotSupportedError') {
                errorMsg = 'Este dispositivo no soporta autenticación biométrica';
            } else if (error.message) {
                errorMsg = error.message;
            }

            this.showError(errorMessage, errorMsg);
        } finally {
            this.setButtonLoading(biometricBtn, false);
        }
    },

    // ==========================================================================
    // PÁGINA DE REGISTRO
    // ==========================================================================

    /**
     * Inicializa la página de registro
     */
    initRegisterPage() {
        // Verificar si ya hay sesión activa
        this.checkExistingSession();

        // Configurar formulario de registro
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }

        // Configurar validación de contraseña en tiempo real
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => this.validatePasswordStrength(e.target.value));
        }

        // Configurar toggle de contraseña
        this.setupPasswordToggle();

        // Configurar botones de biometría
        const setupBiometricBtn = document.getElementById('setupBiometricBtn');
        if (setupBiometricBtn) {
            setupBiometricBtn.addEventListener('click', () => this.handleBiometricSetup());
        }

        const skipBiometricBtn = document.getElementById('skipBiometricBtn');
        if (skipBiometricBtn) {
            skipBiometricBtn.addEventListener('click', () => this.skipBiometricSetup());
        }

        const goToDashboardBtn = document.getElementById('goToDashboardBtn');
        if (goToDashboardBtn) {
            goToDashboardBtn.addEventListener('click', () => {
                window.location.href = '/dashboard';
            });
        }
    },

    /**
     * Valida la fortaleza de la contraseña
     */
    validatePasswordStrength(password) {
        const requirements = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[@$!%*?&]/.test(password)
        };

        // Actualizar indicadores visuales
        Object.keys(requirements).forEach(req => {
            const element = document.querySelector(`[data-req="${req}"]`);
            if (element) {
                element.classList.toggle('met', requirements[req]);
            }
        });

        // Calcular fortaleza
        const metRequirements = Object.values(requirements).filter(Boolean).length;
        const strengthFill = document.getElementById('strengthFill');
        const strengthText = document.getElementById('strengthText');

        if (strengthFill && strengthText) {
            strengthFill.className = 'strength-fill';

            if (metRequirements === 0) {
                strengthText.textContent = 'Ingresa una contraseña';
            } else if (metRequirements <= 2) {
                strengthFill.classList.add('weak');
                strengthText.textContent = 'Débil';
            } else if (metRequirements <= 3) {
                strengthFill.classList.add('fair');
                strengthText.textContent = 'Regular';
            } else if (metRequirements <= 4) {
                strengthFill.classList.add('good');
                strengthText.textContent = 'Buena';
            } else {
                strengthFill.classList.add('strong');
                strengthText.textContent = 'Excelente';
            }
        }

        return Object.values(requirements).every(Boolean);
    },

    /**
     * Maneja el envío del formulario de registro
     */
    async handleRegister(event) {
        event.preventDefault();

        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const acceptTerms = document.getElementById('acceptTerms').checked;
        const registerBtn = document.getElementById('registerBtn');
        const errorMessage = document.getElementById('errorMessage');

        // Validaciones
        if (!username || !email || !password || !confirmPassword) {
            this.showError(errorMessage, 'Por favor, completa todos los campos');
            return;
        }

        if (!this.validatePasswordStrength(password)) {
            this.showError(errorMessage, 'La contraseña no cumple los requisitos mínimos');
            return;
        }

        if (password !== confirmPassword) {
            this.showError(errorMessage, 'Las contraseñas no coinciden');
            return;
        }

        if (!acceptTerms) {
            this.showError(errorMessage, 'Debes aceptar los términos y condiciones');
            return;
        }

        this.setButtonLoading(registerBtn, true);
        this.hideError(errorMessage);

        try {
            const response = await fetch(`${this.API_BASE}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({ username, email, password }),
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok) {
                this.currentUser = data.user;
                this.showToast('Cuenta creada exitosamente', 'success');

                // Mostrar paso de biometría
                this.updateProgressStep(2);

                if (this.webAuthnSupported) {
                    // Mostrar opción de configurar biometría
                    document.getElementById('registerForm').style.display = 'none';
                    document.getElementById('biometricSetup').style.display = 'block';
                } else {
                    // Sin biometría, ir al éxito
                    this.showSuccessMessage();
                }
            } else {
                let errorMsg = data.error || 'Error al registrar';
                if (data.details && data.details.length > 0) {
                    errorMsg = data.details.map(d => d.message).join('. ');
                }
                this.showError(errorMessage, errorMsg);
            }
        } catch (error) {
            console.error('Error en registro:', error);
            this.showError(errorMessage, 'Error de conexión. Intenta de nuevo.');
        } finally {
            this.setButtonLoading(registerBtn, false);
        }
    },

    /**
     * Maneja la configuración de biometría después del registro
     */
    async handleBiometricSetup() {
        const setupBtn = document.getElementById('setupBiometricBtn');
        this.setButtonLoading(setupBtn, true);

        try {
            // 1. Obtener opciones de registro del servidor
            const optionsResponse = await fetch(`${this.API_BASE}/auth/webauthn/register/options`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                credentials: 'include'
            });

            const optionsData = await optionsResponse.json();

            if (!optionsResponse.ok) {
                throw new Error(optionsData.error || 'Error obteniendo opciones');
            }

            // 2. Iniciar registro WebAuthn
            const { startRegistration } = SimpleWebAuthnBrowser;
            const attestation = await startRegistration(optionsData.options);

            // 3. Verificar con el servidor
            const verifyResponse = await fetch(`${this.API_BASE}/auth/webauthn/register/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({
                    response: attestation,
                    challengeId: optionsData.challengeId
                }),
                credentials: 'include'
            });

            const verifyData = await verifyResponse.json();

            if (verifyResponse.ok) {
                this.showToast('Biometría configurada exitosamente', 'success');
                this.showSuccessMessage();
            } else {
                throw new Error(verifyData.error || 'Error de verificación');
            }
        } catch (error) {
            console.error('Error configurando biometría:', error);

            let errorMsg = 'Error configurando biometría';
            if (error.name === 'NotAllowedError') {
                errorMsg = 'Configuración cancelada';
            } else if (error.message) {
                errorMsg = error.message;
            }

            this.showToast(errorMsg, 'error');
        } finally {
            this.setButtonLoading(setupBtn, false);
        }
    },

    /**
     * Salta la configuración de biometría
     */
    skipBiometricSetup() {
        this.showSuccessMessage();
    },

    /**
     * Muestra el mensaje de éxito
     */
    showSuccessMessage() {
        this.updateProgressStep(3);
        document.getElementById('biometricSetup').style.display = 'none';
        document.getElementById('successMessage').style.display = 'block';
    },

    /**
     * Actualiza el paso actual en el indicador de progreso
     */
    updateProgressStep(step) {
        const steps = document.querySelectorAll('.step');
        steps.forEach((s, index) => {
            s.classList.remove('active', 'completed');
            if (index + 1 < step) {
                s.classList.add('completed');
            } else if (index + 1 === step) {
                s.classList.add('active');
            }
        });
    },

    // ==========================================================================
    // DASHBOARD
    // ==========================================================================

    /**
     * Inicializa el dashboard
     */
    async initDashboard() {
        // Verificar autenticación
        const isAuthenticated = await this.verifyAuthentication();

        if (!isAuthenticated) {
            window.location.href = '/';
            return;
        }

        // Cargar datos del usuario
        await this.loadUserData();

        // Configurar menú de usuario
        this.setupUserMenu();

        // Configurar botón de logout
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
        }

        // Configurar configuración de biometría
        this.setupBiometricDashboard();

        // Iniciar temporizador de sesión
        this.startSessionTimer();

        // Ocultar overlay de carga
        this.hideLoadingOverlay();
    },

    /**
     * Verifica si el usuario está autenticado
     */
    async verifyAuthentication() {
        try {
            const response = await fetch(`${this.API_BASE}/auth/me`, {
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                this.currentUser = data.user;
                return true;
            }

            // Intentar refresh token
            const refreshResponse = await fetch(`${this.API_BASE}/auth/refresh`, {
                method: 'POST',
                credentials: 'include'
            });

            if (refreshResponse.ok) {
                return this.verifyAuthentication();
            }

            return false;
        } catch (error) {
            console.error('Error verificando autenticación:', error);
            return false;
        }
    },

    /**
     * Carga los datos del usuario en el dashboard
     */
    async loadUserData() {
        if (!this.currentUser) return;

        // Nombre de usuario
        const welcomeName = document.getElementById('welcomeName');
        const userName = document.getElementById('userName');
        const userAvatar = document.getElementById('userAvatar');

        if (welcomeName) welcomeName.textContent = this.currentUser.username;
        if (userName) userName.textContent = this.currentUser.username;
        if (userAvatar) userAvatar.querySelector('span').textContent = this.currentUser.username.charAt(0).toUpperCase();

        // Estado de biometría
        const biometricStatus = document.getElementById('biometricStatus');
        const biometricCheckItem = document.getElementById('biometricCheckItem');
        const biometricStatusIcon = document.getElementById('biometricStatusIcon');
        const setupBiometricDashboard = document.getElementById('setupBiometricDashboard');
        const noDevicesMessage = document.getElementById('noDevicesMessage');
        const devicesList = document.getElementById('devicesList');

        if (this.currentUser.hasBiometric) {
            if (biometricStatus) biometricStatus.textContent = 'Activa';
            if (biometricCheckItem) biometricCheckItem.classList.add('checked');
            if (setupBiometricDashboard) setupBiometricDashboard.style.display = 'none';

            // Mostrar dispositivos
            if (this.currentUser.biometricDevices && this.currentUser.biometricDevices.length > 0) {
                if (noDevicesMessage) noDevicesMessage.style.display = 'none';

                this.currentUser.biometricDevices.forEach(device => {
                    const deviceCard = document.createElement('div');
                    deviceCard.className = 'device-card';
                    deviceCard.innerHTML = `
                        <div class="device-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 11c0-1.1-.9-2-2-2s-2 .9-2 2c0 .7.4 1.4 1 1.7V14h2v-1.3c.6-.3 1-1 1-1.7z"/>
                                <path d="M7 3v2.4A5.5 5.5 0 002 11c0 2.6 1.8 4.7 4.2 5.3.2 1.6 1.6 2.7 3.1 2.7H11v2h2v-2h1.7c1.5 0 2.9-1.1 3.1-2.7 2.4-.6 4.2-2.7 4.2-5.3 0-2.5-1.7-4.5-4-5.2V3h-2v1.1c-.6-.1-1.3-.1-2-.1s-1.4 0-2 .1V3H7z"/>
                            </svg>
                        </div>
                        <div class="device-info">
                            <h4>${device.device_type || 'Dispositivo biométrico'}</h4>
                            <p>Registrado: ${new Date(device.created_at).toLocaleDateString()}</p>
                        </div>
                    `;
                    if (devicesList) devicesList.insertBefore(deviceCard, noDevicesMessage);
                });
            }
        } else {
            if (biometricStatus) biometricStatus.textContent = 'No configurada';
            if (biometricStatusIcon) biometricStatusIcon.classList.remove('purple');
            if (this.webAuthnSupported && setupBiometricDashboard) {
                setupBiometricDashboard.style.display = 'flex';
            }
        }
    },

    /**
     * Configura el menú de usuario
     */
    setupUserMenu() {
        const navUser = document.getElementById('navUser');
        const navDropdown = document.getElementById('navDropdown');

        if (navUser && navDropdown) {
            navUser.addEventListener('click', () => {
                navUser.classList.toggle('open');
                navDropdown.classList.toggle('open');
            });

            // Cerrar al hacer clic fuera
            document.addEventListener('click', (e) => {
                if (!navUser.contains(e.target) && !navDropdown.contains(e.target)) {
                    navUser.classList.remove('open');
                    navDropdown.classList.remove('open');
                }
            });
        }
    },

    /**
     * Configura la biometría desde el dashboard
     */
    setupBiometricDashboard() {
        const setupBtn = document.getElementById('setupBiometricDashboard');
        const addDeviceBtn = document.getElementById('addDeviceBtn');

        const handleSetup = async () => {
            await this.handleBiometricSetup();
            // Recargar para mostrar cambios
            window.location.reload();
        };

        if (setupBtn) {
            setupBtn.addEventListener('click', handleSetup);
        }

        if (addDeviceBtn) {
            addDeviceBtn.addEventListener('click', handleSetup);
        }
    },

    /**
     * Inicia el temporizador de sesión
     */
    startSessionTimer() {
        const tokenExpiry = document.getElementById('tokenExpiry');

        let timeLeft = 15 * 60; // 15 minutos en segundos

        const updateTimer = () => {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;

            if (tokenExpiry) {
                tokenExpiry.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            }

            if (timeLeft <= 0) {
                // Renovar token
                this.refreshToken();
                timeLeft = 15 * 60;
            }

            timeLeft--;
        };

        updateTimer();
        this.sessionTimer = setInterval(updateTimer, 1000);
    },

    /**
     * Renueva el token de acceso
     */
    async refreshToken() {
        try {
            const response = await fetch(`${this.API_BASE}/auth/refresh`, {
                method: 'POST',
                credentials: 'include'
            });

            if (!response.ok) {
                // Token de refresh inválido, cerrar sesión
                this.handleLogout();
            }
        } catch (error) {
            console.error('Error renovando token:', error);
        }
    },

    /**
     * Maneja el cierre de sesión
     */
    async handleLogout() {
        try {
            await fetch(`${this.API_BASE}/auth/logout`, {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': this.csrfToken
                },
                credentials: 'include'
            });
        } catch (error) {
            console.error('Error en logout:', error);
        } finally {
            if (this.sessionTimer) {
                clearInterval(this.sessionTimer);
            }
            window.location.href = '/';
        }
    },

    /**
     * Oculta el overlay de carga
     */
    hideLoadingOverlay() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.remove('visible');
        }
    },

    // ==========================================================================
    // UTILIDADES
    // ==========================================================================

    /**
     * Configura eventos globales
     */
    setupGlobalEvents() {
        // Manejar visibilidad de página para refrescar token
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible' && this.pageType === 'dashboard') {
                this.verifyAuthentication();
            }
        });
    },

    /**
     * Configura el toggle de contraseña
     */
    setupPasswordToggle() {
        const toggleButtons = document.querySelectorAll('.toggle-password');

        toggleButtons.forEach(button => {
            button.addEventListener('click', () => {
                const input = button.previousElementSibling;

                if (input && input.type === 'password') {
                    input.type = 'text';
                    button.classList.add('active');
                } else if (input) {
                    input.type = 'password';
                    button.classList.remove('active');
                }
            });
        });
    },

    /**
     * Muestra un mensaje de error
     */
    showError(element, message) {
        if (element) {
            element.textContent = message;
            element.classList.add('visible');
        }
    },

    /**
     * Oculta el mensaje de error
     */
    hideError(element) {
        if (element) {
            element.classList.remove('visible');
        }
    },

    /**
     * Establece el estado de carga de un botón
     */
    setButtonLoading(button, loading) {
        if (button) {
            button.classList.toggle('loading', loading);
            button.disabled = loading;
        }
    },

    /**
     * Muestra una notificación toast
     */
    showToast(message, type = 'success') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icon = type === 'success'
            ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
            : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

        toast.innerHTML = `
            <span class="toast-icon">${icon}</span>
            <span class="toast-message">${message}</span>
        `;

        container.appendChild(toast);

        // Remover después de 3 segundos
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
};

// Exportar para uso global
window.Auth = Auth;
