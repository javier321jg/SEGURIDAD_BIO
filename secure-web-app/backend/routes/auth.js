/**
 * =============================================================================
 * RUTAS DE AUTENTICACIÓN
 * =============================================================================
 *
 * Este módulo implementa todas las rutas de autenticación:
 * - Registro de usuarios con contraseña
 * - Login con contraseña
 * - Registro de credenciales biométricas (WebAuthn)
 * - Login con biometría
 * - Refresh de tokens
 * - Logout
 *
 * Todas las rutas incluyen protección contra ataques
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');

// Importar utilidades y middleware
const webauthn = require('../utils/webauthn');
const logger = require('../utils/logger');
const {
    loginRateLimiter,
    registerValidators,
    loginValidators,
    validateRequest,
    verifyJWT
} = require('../middleware/security');

// Conexión a base de datos
const db = new Database('./database.sqlite');

// Configuración JWT
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = '15m'; // 15 minutos
const REFRESH_TOKEN_EXPIRES_IN = 7 * 24 * 60 * 60 * 1000; // 7 días en ms
const BCRYPT_SALT_ROUNDS = 12;

// =============================================================================
// REGISTRO DE USUARIO
// =============================================================================

/**
 * POST /api/auth/register
 * Registra un nuevo usuario con contraseña
 */
router.post('/register',
    registerValidators,
    validateRequest,
    async (req, res) => {
        try {
            const { username, email, password } = req.body;

            // Verificar si el usuario ya existe
            const existingUser = db.prepare(
                'SELECT id FROM users WHERE username = ? OR email = ?'
            ).get(username, email);

            if (existingUser) {
                logger.logSecurityAlert({
                    type: 'DUPLICATE_REGISTRATION',
                    severity: 'low',
                    message: 'Intento de registro con usuario/email existente',
                    ip: req.ip,
                    details: { username, email }
                });

                return res.status(409).json({
                    error: 'El nombre de usuario o email ya está en uso',
                    code: 'USER_EXISTS'
                });
            }

            // Hash de la contraseña con bcrypt (12 salt rounds)
            const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

            // Crear usuario
            const userId = uuidv4();
            const insertStmt = db.prepare(`
                INSERT INTO users (id, username, email, password_hash)
                VALUES (?, ?, ?, ?)
            `);
            insertStmt.run(userId, username, email, passwordHash);

            // Log de auditoría
            logger.logUserRegistration({
                userId,
                username,
                email,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                biometricEnabled: false
            });

            // Generar tokens
            const { accessToken, refreshToken } = generateTokens(userId, username, email);

            // Guardar refresh token
            saveRefreshToken(userId, refreshToken);

            // Establecer cookies seguras
            setAuthCookies(res, accessToken, refreshToken);

            res.status(201).json({
                success: true,
                message: 'Usuario registrado exitosamente',
                user: {
                    id: userId,
                    username,
                    email
                }
            });

        } catch (error) {
            logger.error('Error en registro de usuario', {
                error: error.message,
                stack: error.stack
            });

            res.status(500).json({
                error: 'Error al registrar usuario',
                code: 'REGISTRATION_ERROR'
            });
        }
    }
);

// =============================================================================
// LOGIN CON CONTRASEÑA
// =============================================================================

/**
 * POST /api/auth/login
 * Login con nombre de usuario y contraseña
 */
router.post('/login',
    loginRateLimiter,
    loginValidators,
    validateRequest,
    async (req, res) => {
        try {
            const { username, password } = req.body;

            // Buscar usuario
            const user = db.prepare(
                'SELECT * FROM users WHERE username = ? OR email = ?'
            ).get(username, username);

            if (!user) {
                logger.logLoginAttempt({
                    username,
                    success: false,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    method: 'password'
                });

                return res.status(401).json({
                    error: 'Credenciales inválidas',
                    code: 'INVALID_CREDENTIALS'
                });
            }

            // Verificar si la cuenta está bloqueada
            if (user.locked_until && new Date(user.locked_until) > new Date()) {
                const remainingTime = Math.ceil((new Date(user.locked_until) - new Date()) / 1000 / 60);

                logger.logSecurityAlert({
                    type: 'LOCKED_ACCOUNT_ACCESS',
                    severity: 'medium',
                    message: 'Intento de acceso a cuenta bloqueada',
                    ip: req.ip,
                    userId: user.id
                });

                return res.status(423).json({
                    error: `Cuenta bloqueada. Intenta de nuevo en ${remainingTime} minutos`,
                    code: 'ACCOUNT_LOCKED'
                });
            }

            // Verificar contraseña
            const passwordValid = await bcrypt.compare(password, user.password_hash);

            if (!passwordValid) {
                // Incrementar intentos fallidos
                const newFailedAttempts = user.failed_login_attempts + 1;
                let lockUntil = null;

                // Bloquear cuenta después de 5 intentos fallidos
                if (newFailedAttempts >= 5) {
                    lockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutos

                    logger.logAccountLock({
                        userId: user.id,
                        username: user.username,
                        reason: 'Demasiados intentos fallidos',
                        duration: '15 minutos',
                        ip: req.ip
                    });
                }

                db.prepare(`
                    UPDATE users
                    SET failed_login_attempts = ?, locked_until = ?
                    WHERE id = ?
                `).run(newFailedAttempts, lockUntil, user.id);

                logger.logLoginAttempt({
                    userId: user.id,
                    username: user.username,
                    success: false,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    method: 'password'
                });

                return res.status(401).json({
                    error: 'Credenciales inválidas',
                    code: 'INVALID_CREDENTIALS',
                    remainingAttempts: Math.max(0, 5 - newFailedAttempts)
                });
            }

            // Login exitoso - resetear intentos fallidos
            db.prepare(`
                UPDATE users
                SET failed_login_attempts = 0, locked_until = NULL
                WHERE id = ?
            `).run(user.id);

            // Generar tokens
            const { accessToken, refreshToken } = generateTokens(user.id, user.username, user.email);

            // Guardar refresh token
            saveRefreshToken(user.id, refreshToken);

            // Establecer cookies seguras
            setAuthCookies(res, accessToken, refreshToken);

            logger.logLoginAttempt({
                userId: user.id,
                username: user.username,
                success: true,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                method: 'password'
            });

            // Verificar si tiene credenciales biométricas
            const hasBiometric = db.prepare(
                'SELECT COUNT(*) as count FROM webauthn_credentials WHERE user_id = ?'
            ).get(user.id).count > 0;

            res.json({
                success: true,
                message: 'Login exitoso',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    hasBiometric
                },
                accessToken
            });

        } catch (error) {
            logger.error('Error en login', {
                error: error.message,
                stack: error.stack
            });

            res.status(500).json({
                error: 'Error al iniciar sesión',
                code: 'LOGIN_ERROR'
            });
        }
    }
);

// =============================================================================
// WEBAUTHN - REGISTRO DE CREDENCIAL BIOMÉTRICA
// =============================================================================

/**
 * POST /api/auth/webauthn/register/options
 * Genera opciones para registrar una nueva credencial biométrica
 */
router.post('/webauthn/register/options',
    verifyJWT,
    async (req, res) => {
        try {
            const user = req.user;

            // Obtener credenciales existentes
            const existingCredentials = db.prepare(
                'SELECT * FROM webauthn_credentials WHERE user_id = ?'
            ).all(user.id);

            // Generar opciones
            const result = await webauthn.generateRegistrationOptionsForUser(
                user,
                existingCredentials
            );

            if (!result.success) {
                return res.status(500).json({
                    error: 'Error generando opciones de registro',
                    code: 'WEBAUTHN_OPTIONS_ERROR'
                });
            }

            // Guardar challenge temporalmente
            const challengeId = uuidv4();
            db.prepare(`
                INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at)
                VALUES (?, ?, ?, 'registration', datetime('now', '+5 minutes'))
            `).run(challengeId, user.id, result.options.challenge);

            res.json({
                success: true,
                options: result.options,
                challengeId
            });

        } catch (error) {
            logger.error('Error en opciones de registro WebAuthn', {
                error: error.message
            });

            res.status(500).json({
                error: 'Error en configuración biométrica',
                code: 'WEBAUTHN_ERROR'
            });
        }
    }
);

/**
 * POST /api/auth/webauthn/register/verify
 * Verifica y guarda la credencial biométrica
 */
router.post('/webauthn/register/verify',
    verifyJWT,
    async (req, res) => {
        try {
            const user = req.user;
            const { response: attestationResponse, challengeId } = req.body;

            // Obtener challenge guardado
            const challenge = db.prepare(
                'SELECT * FROM webauthn_challenges WHERE id = ? AND user_id = ? AND type = ?'
            ).get(challengeId, user.id, 'registration');

            if (!challenge) {
                return res.status(400).json({
                    error: 'Challenge no encontrado o expirado',
                    code: 'CHALLENGE_NOT_FOUND'
                });
            }

            // Verificar respuesta
            const result = await webauthn.verifyRegistration(
                attestationResponse,
                challenge.challenge
            );

            // Eliminar challenge usado
            db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(challengeId);

            if (!result.success || !result.verified) {
                logger.logSecurityAlert({
                    type: 'WEBAUTHN_REGISTRATION_FAILED',
                    severity: 'medium',
                    message: 'Fallo en verificación de registro biométrico',
                    ip: req.ip,
                    userId: user.id
                });

                return res.status(400).json({
                    error: 'Verificación de credencial fallida',
                    code: 'VERIFICATION_FAILED'
                });
            }

            // Detectar tipo de dispositivo
            const deviceType = webauthn.detectDeviceType(req.get('User-Agent'));

            // Guardar credencial
            const credentialId = uuidv4();
            db.prepare(`
                INSERT INTO webauthn_credentials
                (id, user_id, credential_id, public_key, counter, device_type)
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                credentialId,
                user.id,
                result.credential.credentialId,
                result.credential.publicKey,
                result.credential.counter,
                deviceType
            );

            logger.logBiometricRegistration({
                userId: user.id,
                username: user.username,
                deviceType,
                credentialId: result.credential.credentialId,
                ip: req.ip
            });

            res.json({
                success: true,
                message: 'Credencial biométrica registrada exitosamente',
                deviceType
            });

        } catch (error) {
            logger.error('Error verificando registro WebAuthn', {
                error: error.message
            });

            res.status(500).json({
                error: 'Error al registrar credencial biométrica',
                code: 'WEBAUTHN_VERIFY_ERROR'
            });
        }
    }
);

// =============================================================================
// WEBAUTHN - AUTENTICACIÓN BIOMÉTRICA
// =============================================================================

/**
 * POST /api/auth/webauthn/login/options
 * Genera opciones para autenticación biométrica
 */
router.post('/webauthn/login/options',
    loginRateLimiter,
    async (req, res) => {
        try {
            const { username } = req.body;

            // Buscar usuario
            const user = db.prepare(
                'SELECT * FROM users WHERE username = ? OR email = ?'
            ).get(username, username);

            if (!user) {
                // Por seguridad, no revelar si el usuario existe
                return res.status(401).json({
                    error: 'Usuario no encontrado o sin biometría configurada',
                    code: 'USER_NOT_FOUND'
                });
            }

            // Obtener credenciales del usuario
            const credentials = db.prepare(
                'SELECT * FROM webauthn_credentials WHERE user_id = ?'
            ).all(user.id);

            if (credentials.length === 0) {
                return res.status(400).json({
                    error: 'No hay credenciales biométricas configuradas',
                    code: 'NO_CREDENTIALS'
                });
            }

            // Generar opciones
            const result = await webauthn.generateAuthenticationOptionsForUser(credentials);

            if (!result.success) {
                return res.status(500).json({
                    error: 'Error generando opciones de autenticación',
                    code: 'WEBAUTHN_OPTIONS_ERROR'
                });
            }

            // Guardar challenge temporalmente
            const challengeId = uuidv4();
            db.prepare(`
                INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at)
                VALUES (?, ?, ?, 'authentication', datetime('now', '+5 minutes'))
            `).run(challengeId, user.id, result.options.challenge);

            res.json({
                success: true,
                options: result.options,
                challengeId,
                userId: user.id
            });

        } catch (error) {
            logger.error('Error en opciones de login WebAuthn', {
                error: error.message
            });

            res.status(500).json({
                error: 'Error en autenticación biométrica',
                code: 'WEBAUTHN_ERROR'
            });
        }
    }
);

/**
 * POST /api/auth/webauthn/login/verify
 * Verifica la autenticación biométrica
 */
router.post('/webauthn/login/verify',
    loginRateLimiter,
    async (req, res) => {
        try {
            const { response: assertionResponse, challengeId, userId } = req.body;

            // Obtener challenge guardado
            const challenge = db.prepare(
                'SELECT * FROM webauthn_challenges WHERE id = ? AND user_id = ? AND type = ?'
            ).get(challengeId, userId, 'authentication');

            if (!challenge) {
                return res.status(400).json({
                    error: 'Challenge no encontrado o expirado',
                    code: 'CHALLENGE_NOT_FOUND'
                });
            }

            // Obtener credencial usada
            const credentialId = assertionResponse.id;
            const credential = db.prepare(
                'SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?'
            ).get(credentialId, userId);

            if (!credential) {
                return res.status(400).json({
                    error: 'Credencial no encontrada',
                    code: 'CREDENTIAL_NOT_FOUND'
                });
            }

            // Verificar respuesta
            const result = await webauthn.verifyAuthentication(
                assertionResponse,
                challenge.challenge,
                credential
            );

            // Eliminar challenge usado
            db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(challengeId);

            if (!result.success || !result.verified) {
                logger.logBiometricUsage({
                    userId,
                    username: 'unknown',
                    success: false,
                    deviceType: credential.device_type,
                    ip: req.ip
                });

                return res.status(401).json({
                    error: 'Autenticación biométrica fallida',
                    code: 'AUTH_FAILED'
                });
            }

            // Actualizar contador de la credencial
            db.prepare(`
                UPDATE webauthn_credentials
                SET counter = ?, last_used_at = datetime('now')
                WHERE id = ?
            `).run(result.newCounter, credential.id);

            // Obtener datos del usuario
            const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

            // Generar tokens
            const { accessToken, refreshToken } = generateTokens(user.id, user.username, user.email);

            // Guardar refresh token
            saveRefreshToken(user.id, refreshToken);

            // Establecer cookies seguras
            setAuthCookies(res, accessToken, refreshToken);

            logger.logBiometricUsage({
                userId: user.id,
                username: user.username,
                success: true,
                deviceType: credential.device_type,
                ip: req.ip
            });

            logger.logLoginAttempt({
                userId: user.id,
                username: user.username,
                success: true,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                method: 'biometric'
            });

            res.json({
                success: true,
                message: 'Autenticación biométrica exitosa',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    hasBiometric: true
                },
                accessToken
            });

        } catch (error) {
            logger.error('Error verificando login WebAuthn', {
                error: error.message
            });

            res.status(500).json({
                error: 'Error en autenticación biométrica',
                code: 'WEBAUTHN_VERIFY_ERROR'
            });
        }
    }
);

// =============================================================================
// REFRESH TOKEN
// =============================================================================

/**
 * POST /api/auth/refresh
 * Renueva el access token usando el refresh token
 */
router.post('/refresh', async (req, res) => {
    try {
        // Obtener refresh token de la cookie
        const refreshToken = req.cookies['refresh-token'];

        if (!refreshToken) {
            return res.status(401).json({
                error: 'Refresh token requerido',
                code: 'REFRESH_TOKEN_REQUIRED'
            });
        }

        // Verificar que el refresh token existe y es válido
        const tokenHash = hashToken(refreshToken);
        const storedToken = db.prepare(
            'SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0'
        ).get(tokenHash);

        if (!storedToken) {
            return res.status(401).json({
                error: 'Refresh token inválido',
                code: 'INVALID_REFRESH_TOKEN'
            });
        }

        // Verificar expiración
        if (new Date(storedToken.expires_at) < new Date()) {
            db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(storedToken.id);

            return res.status(401).json({
                error: 'Refresh token expirado',
                code: 'REFRESH_TOKEN_EXPIRED'
            });
        }

        // Obtener usuario
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);

        if (!user || !user.is_active) {
            return res.status(401).json({
                error: 'Usuario no encontrado o inactivo',
                code: 'USER_NOT_FOUND'
            });
        }

        // Revocar el refresh token actual (rotación de tokens)
        db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(storedToken.id);

        // Generar nuevos tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(
            user.id,
            user.username,
            user.email
        );

        // Guardar nuevo refresh token
        saveRefreshToken(user.id, newRefreshToken);

        // Establecer cookies seguras
        setAuthCookies(res, accessToken, newRefreshToken);

        logger.logLoginAttempt({
            userId: user.id,
            username: user.username,
            success: true,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            method: 'refresh_token'
        });

        res.json({
            success: true,
            message: 'Token renovado exitosamente',
            accessToken
        });

    } catch (error) {
        logger.error('Error en refresh token', {
            error: error.message
        });

        res.status(500).json({
            error: 'Error al renovar token',
            code: 'REFRESH_ERROR'
        });
    }
});

// =============================================================================
// LOGOUT
// =============================================================================

/**
 * POST /api/auth/logout
 * Cierra la sesión del usuario
 */
router.post('/logout', verifyJWT, async (req, res) => {
    try {
        const user = req.user;
        const refreshToken = req.cookies['refresh-token'];

        // Revocar refresh token
        if (refreshToken) {
            const tokenHash = hashToken(refreshToken);
            db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').run(tokenHash);
        }

        // Limpiar cookies
        res.clearCookie('access-token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });
        res.clearCookie('refresh-token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        logger.logLogout({
            userId: user.id,
            username: user.username,
            ip: req.ip
        });

        res.json({
            success: true,
            message: 'Sesión cerrada exitosamente'
        });

    } catch (error) {
        logger.error('Error en logout', {
            error: error.message
        });

        res.status(500).json({
            error: 'Error al cerrar sesión',
            code: 'LOGOUT_ERROR'
        });
    }
});

// =============================================================================
// VERIFICAR SESIÓN
// =============================================================================

/**
 * GET /api/auth/me
 * Obtiene información del usuario autenticado
 */
router.get('/me', verifyJWT, async (req, res) => {
    try {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

        if (!user) {
            return res.status(404).json({
                error: 'Usuario no encontrado',
                code: 'USER_NOT_FOUND'
            });
        }

        // Obtener credenciales biométricas
        const credentials = db.prepare(
            'SELECT id, device_type, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ?'
        ).all(user.id);

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                createdAt: user.created_at,
                hasBiometric: credentials.length > 0,
                biometricDevices: credentials
            }
        });

    } catch (error) {
        logger.error('Error obteniendo usuario', {
            error: error.message
        });

        res.status(500).json({
            error: 'Error al obtener información del usuario',
            code: 'USER_ERROR'
        });
    }
});

// =============================================================================
// FUNCIONES AUXILIARES
// =============================================================================

/**
 * Genera tokens JWT de acceso y refresh
 */
function generateTokens(userId, username, email) {
    const accessToken = jwt.sign(
        {
            sub: userId,
            username,
            email,
            type: 'access'
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );

    const refreshToken = uuidv4() + '-' + uuidv4();

    return { accessToken, refreshToken };
}

/**
 * Guarda el refresh token en la base de datos
 */
function saveRefreshToken(userId, refreshToken) {
    const tokenHash = hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN).toISOString();

    db.prepare(`
        INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
        VALUES (?, ?, ?, ?)
    `).run(uuidv4(), userId, tokenHash, expiresAt);
}

/**
 * Hash simple del token para almacenamiento seguro
 */
function hashToken(token) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Establece las cookies de autenticación
 */
function setAuthCookies(res, accessToken, refreshToken) {
    const isProduction = process.env.NODE_ENV === 'production';

    // Cookie de access token (15 minutos)
    res.cookie('access-token', accessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutos
    });

    // Cookie de refresh token (7 días)
    res.cookie('refresh-token', refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
        path: '/api/auth/refresh' // Solo se envía en la ruta de refresh
    });
}

module.exports = router;
