/**
 * =============================================================================
 * MIDDLEWARE DE SEGURIDAD
 * =============================================================================
 *
 * Este módulo implementa múltiples capas de protección:
 * - Rate Limiting: Máximo 5 intentos de login por minuto
 * - Protección CSRF: Tokens únicos por sesión
 * - Sanitización de inputs: Prevención XSS y SQL Injection
 * - Logging de requests: Auditoría completa
 * - Verificación JWT: Autenticación de tokens
 */

const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

// =============================================================================
// RATE LIMITING
// =============================================================================

/**
 * Rate limiter para endpoints de autenticación
 * Máximo 5 intentos por minuto por IP
 */
const rateLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    max: 5, // 5 intentos
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,

    // Mensaje personalizado
    message: {
        error: 'Demasiados intentos. Por favor, espera 1 minuto antes de intentar de nuevo.',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: 60
    },

    // Callback cuando se excede el límite
    handler: (req, res, next, options) => {
        logger.logSecurityAlert({
            type: 'RATE_LIMIT_EXCEEDED',
            severity: 'medium',
            message: `Rate limit excedido para IP: ${req.ip}`,
            ip: req.ip,
            details: {
                path: req.path,
                method: req.method
            }
        });

        res.status(429).json(options.message);
    },

    // Identificar por IP
    keyGenerator: (req) => {
        return req.ip || req.connection.remoteAddress;
    },

    // Saltar para ciertas rutas
    skip: (req) => {
        // No aplicar rate limit a rutas públicas estáticas
        const publicRoutes = ['/api/health', '/api/csrf-token'];
        return publicRoutes.includes(req.path);
    }
});

/**
 * Rate limiter más estricto para login
 */
const loginRateLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    max: 3, // Solo 3 intentos de login por minuto
    standardHeaders: true,
    legacyHeaders: false,

    message: {
        error: 'Demasiados intentos de inicio de sesión. Espera 1 minuto.',
        code: 'LOGIN_RATE_LIMIT_EXCEEDED',
        retryAfter: 60
    },

    handler: (req, res, next, options) => {
        logger.logSecurityAlert({
            type: 'LOGIN_BRUTE_FORCE_ATTEMPT',
            severity: 'high',
            message: `Posible ataque de fuerza bruta desde IP: ${req.ip}`,
            ip: req.ip,
            details: {
                username: req.body?.username || 'unknown'
            }
        });

        res.status(429).json(options.message);
    },

    keyGenerator: (req) => {
        // Combinar IP + username para rate limiting más preciso
        const username = req.body?.username || '';
        return `${req.ip}-${username}`;
    }
});

// =============================================================================
// PROTECCIÓN CSRF
// =============================================================================

// Almacén en memoria para tokens CSRF (en producción usar Redis)
const csrfTokens = new Map();

/**
 * Middleware de protección CSRF
 */
const csrfProtection = (req, res, next) => {
    // Métodos seguros no requieren verificación CSRF
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        // Generar token para la sesión
        if (!req.cookies['csrf-token']) {
            const token = uuidv4();
            csrfTokens.set(token, {
                created: Date.now(),
                ip: req.ip
            });

            res.cookie('csrf-token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000 // 15 minutos
            });

            req.csrfToken = token;
        } else {
            req.csrfToken = req.cookies['csrf-token'];
        }

        return next();
    }

    // Para POST, PUT, DELETE - verificar token
    const tokenFromHeader = req.get('X-CSRF-Token');
    const tokenFromCookie = req.cookies['csrf-token'];

    // Verificar que ambos tokens existen y coinciden
    if (!tokenFromHeader || !tokenFromCookie) {
        logger.logSecurityAlert({
            type: 'CSRF_TOKEN_MISSING',
            severity: 'medium',
            message: 'Intento de request sin token CSRF',
            ip: req.ip,
            details: {
                path: req.path,
                method: req.method
            }
        });

        return res.status(403).json({
            error: 'Token CSRF requerido',
            code: 'CSRF_TOKEN_MISSING'
        });
    }

    if (tokenFromHeader !== tokenFromCookie) {
        logger.logSecurityAlert({
            type: 'CSRF_TOKEN_MISMATCH',
            severity: 'high',
            message: 'Token CSRF no coincide',
            ip: req.ip,
            details: {
                path: req.path,
                method: req.method
            }
        });

        return res.status(403).json({
            error: 'Token CSRF inválido',
            code: 'CSRF_TOKEN_INVALID'
        });
    }

    // Verificar que el token existe en nuestro almacén
    const storedToken = csrfTokens.get(tokenFromCookie);
    if (!storedToken) {
        return res.status(403).json({
            error: 'Token CSRF expirado o inválido',
            code: 'CSRF_TOKEN_EXPIRED'
        });
    }

    // Verificar que no ha expirado (15 minutos)
    if (Date.now() - storedToken.created > 15 * 60 * 1000) {
        csrfTokens.delete(tokenFromCookie);
        return res.status(403).json({
            error: 'Token CSRF expirado',
            code: 'CSRF_TOKEN_EXPIRED'
        });
    }

    req.csrfToken = tokenFromCookie;
    next();
};

// Limpiar tokens CSRF expirados cada 5 minutos
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of csrfTokens.entries()) {
        if (now - data.created > 15 * 60 * 1000) {
            csrfTokens.delete(token);
        }
    }
}, 5 * 60 * 1000);

// =============================================================================
// SANITIZACIÓN DE INPUTS
// =============================================================================

/**
 * Opciones de configuración XSS
 */
const xssOptions = {
    whiteList: {}, // No permitir ninguna etiqueta HTML
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
};

/**
 * Middleware para sanitizar todos los inputs
 */
const sanitizeInput = (req, res, next) => {
    // Sanitizar body
    if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body);
    }

    // Sanitizar query params
    if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query);
    }

    // Sanitizar params de URL
    if (req.params && typeof req.params === 'object') {
        req.params = sanitizeObject(req.params);
    }

    next();
};

/**
 * Función recursiva para sanitizar objetos
 */
function sanitizeObject(obj) {
    const sanitized = {};

    for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            const value = obj[key];

            // Sanitizar la clave también
            const sanitizedKey = xss(key, xssOptions);

            if (typeof value === 'string') {
                // Sanitizar strings
                sanitized[sanitizedKey] = xss(value, xssOptions)
                    .trim()
                    // Prevenir SQL injection básico
                    .replace(/['";\\]/g, '')
                    // Remover caracteres de control
                    .replace(/[\x00-\x1F\x7F]/g, '');
            } else if (typeof value === 'object' && value !== null) {
                // Recursivamente sanitizar objetos anidados
                sanitized[sanitizedKey] = Array.isArray(value)
                    ? value.map(item => typeof item === 'string' ? xss(item, xssOptions) : item)
                    : sanitizeObject(value);
            } else {
                sanitized[sanitizedKey] = value;
            }
        }
    }

    return sanitized;
}

// =============================================================================
// VALIDADORES DE INPUT
// =============================================================================

/**
 * Validadores para registro de usuario
 */
const registerValidators = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('El nombre de usuario debe tener entre 3 y 30 caracteres')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('El nombre de usuario solo puede contener letras, números y guiones bajos'),

    body('email')
        .trim()
        .isEmail()
        .withMessage('Debe proporcionar un email válido')
        .normalizeEmail(),

    body('password')
        .isLength({ min: 8, max: 128 })
        .withMessage('La contraseña debe tener entre 8 y 128 caracteres')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial')
];

/**
 * Validadores para login
 */
const loginValidators = [
    body('username')
        .trim()
        .notEmpty()
        .withMessage('El nombre de usuario es requerido'),

    body('password')
        .notEmpty()
        .withMessage('La contraseña es requerida')
];

/**
 * Middleware para verificar resultados de validación
 */
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        logger.logSecurityAlert({
            type: 'VALIDATION_ERROR',
            severity: 'low',
            message: 'Errores de validación en request',
            ip: req.ip,
            details: {
                path: req.path,
                errors: errors.array()
            }
        });

        return res.status(400).json({
            error: 'Datos de entrada inválidos',
            code: 'VALIDATION_ERROR',
            details: errors.array().map(err => ({
                field: err.path,
                message: err.msg
            }))
        });
    }

    next();
};

// =============================================================================
// VERIFICACIÓN JWT
// =============================================================================

/**
 * Middleware para verificar JWT
 */
const verifyJWT = (req, res, next) => {
    // Obtener token del header Authorization o de la cookie
    let token = null;

    const authHeader = req.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else if (req.cookies && req.cookies['access-token']) {
        token = req.cookies['access-token'];
    }

    if (!token) {
        logger.logUnauthorizedAccess({
            resource: req.path,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            reason: 'No se proporcionó token de autenticación'
        });

        return res.status(401).json({
            error: 'No autorizado. Token de acceso requerido.',
            code: 'TOKEN_REQUIRED'
        });
    }

    try {
        // Verificar token
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super-secret-jwt-key');

        // Verificar que el token no esté en lista negra (logout)
        // TODO: Implementar blacklist con Redis en producción

        // Agregar usuario al request
        req.user = {
            id: decoded.sub,
            username: decoded.username,
            email: decoded.email
        };

        next();
    } catch (error) {
        let errorMessage = 'Token inválido';
        let errorCode = 'TOKEN_INVALID';

        if (error.name === 'TokenExpiredError') {
            errorMessage = 'Token expirado';
            errorCode = 'TOKEN_EXPIRED';
        } else if (error.name === 'JsonWebTokenError') {
            errorMessage = 'Token malformado';
            errorCode = 'TOKEN_MALFORMED';
        }

        logger.logUnauthorizedAccess({
            resource: req.path,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            reason: errorMessage
        });

        return res.status(401).json({
            error: errorMessage,
            code: errorCode
        });
    }
};

/**
 * Middleware opcional para verificar JWT (no bloquea si no hay token)
 */
const optionalJWT = (req, res, next) => {
    let token = null;

    const authHeader = req.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else if (req.cookies && req.cookies['access-token']) {
        token = req.cookies['access-token'];
    }

    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super-secret-jwt-key');
            req.user = {
                id: decoded.sub,
                username: decoded.username,
                email: decoded.email
            };
        } catch (error) {
            // Token inválido, pero no bloquear
            req.user = null;
        }
    }

    next();
};

// =============================================================================
// REQUEST LOGGER
// =============================================================================

/**
 * Middleware para logging de todas las requests
 */
const requestLogger = (req, res, next) => {
    const startTime = Date.now();

    // Registrar cuando la respuesta termine
    res.on('finish', () => {
        const duration = Date.now() - startTime;

        // Solo loggear rutas de API
        if (req.path.startsWith('/api/')) {
            logger.logAudit({
                action: `${req.method} ${req.path}`,
                userId: req.user?.id || null,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                details: {
                    statusCode: res.statusCode,
                    duration: `${duration}ms`,
                    contentLength: res.get('Content-Length') || 0
                },
                status: res.statusCode < 400 ? 'success' : 'failure'
            });
        }

        // Alertar si la respuesta es muy lenta
        if (duration > 5000) {
            logger.logSecurityAlert({
                type: 'SLOW_REQUEST',
                severity: 'low',
                message: `Request lenta detectada: ${duration}ms`,
                ip: req.ip,
                details: {
                    path: req.path,
                    method: req.method,
                    duration
                }
            });
        }
    });

    next();
};

// =============================================================================
// EXPORTAR MIDDLEWARE
// =============================================================================

module.exports = {
    rateLimiter,
    loginRateLimiter,
    csrfProtection,
    sanitizeInput,
    registerValidators,
    loginValidators,
    validateRequest,
    verifyJWT,
    optionalJWT,
    requestLogger
};
