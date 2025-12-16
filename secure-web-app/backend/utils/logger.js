/**
 * =============================================================================
 * SISTEMA DE LOGGING Y AUDITORÍA
 * =============================================================================
 *
 * Este módulo proporciona logging centralizado para:
 * - Registrar intentos de login (exitosos y fallidos)
 * - Alertas de actividad sospechosa
 * - Logs de auditoría para cumplimiento
 * - Monitoreo de seguridad en tiempo real
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Crear directorio de logs si no existe
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Formato personalizado para logs
const customFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
    let msg = `${timestamp} [${level.toUpperCase()}]: ${message}`;

    if (Object.keys(metadata).length > 0) {
        msg += ` | ${JSON.stringify(metadata)}`;
    }

    return msg;
});

// Configuración del logger principal
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        customFormat
    ),
    defaultMeta: { service: 'secure-web-app' },
    transports: [
        // Logs de errores
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
            tailable: true
        }),

        // Logs de seguridad (intentos de login, alertas)
        new winston.transports.File({
            filename: path.join(logsDir, 'security.log'),
            level: 'warn',
            maxsize: 5242880,
            maxFiles: 10,
            tailable: true
        }),

        // Logs combinados
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log'),
            maxsize: 5242880,
            maxFiles: 5,
            tailable: true
        }),

        // Logs de auditoría
        new winston.transports.File({
            filename: path.join(logsDir, 'audit.log'),
            level: 'info',
            maxsize: 10485760, // 10MB
            maxFiles: 30, // Mantener 30 archivos para cumplimiento
            tailable: true
        })
    ]
});

// Agregar console en desarrollo
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp({ format: 'HH:mm:ss' }),
            customFormat
        )
    }));
}

// =============================================================================
// FUNCIONES ESPECIALIZADAS DE LOGGING
// =============================================================================

/**
 * Registrar intento de login
 * @param {Object} params - Parámetros del intento
 */
logger.logLoginAttempt = function(params) {
    const { userId, username, success, ip, userAgent, method = 'password' } = params;

    const logData = {
        event: 'LOGIN_ATTEMPT',
        userId,
        username,
        success,
        ip,
        userAgent,
        method, // 'password', 'biometric', 'refresh_token'
        timestamp: new Date().toISOString()
    };

    if (success) {
        this.info(`Login exitoso para usuario: ${username}`, logData);
    } else {
        this.warn(`Login fallido para usuario: ${username}`, logData);
    }
};

/**
 * Registrar alerta de seguridad
 * @param {Object} params - Parámetros de la alerta
 */
logger.logSecurityAlert = function(params) {
    const { type, severity, message, ip, userId, details } = params;

    const alertData = {
        event: 'SECURITY_ALERT',
        alertType: type,
        severity, // 'low', 'medium', 'high', 'critical'
        message,
        ip,
        userId,
        details,
        timestamp: new Date().toISOString()
    };

    // Nivel de log según severidad
    switch (severity) {
        case 'critical':
            this.error(`🚨 ALERTA CRÍTICA: ${message}`, alertData);
            break;
        case 'high':
            this.error(`⚠️ ALERTA ALTA: ${message}`, alertData);
            break;
        case 'medium':
            this.warn(`⚡ ALERTA MEDIA: ${message}`, alertData);
            break;
        default:
            this.info(`📋 ALERTA: ${message}`, alertData);
    }
};

/**
 * Registrar evento de auditoría
 * @param {Object} params - Parámetros del evento
 */
logger.logAudit = function(params) {
    const { action, userId, ip, userAgent, details, status } = params;

    const auditData = {
        event: 'AUDIT',
        action,
        userId,
        ip,
        userAgent,
        details,
        status, // 'success', 'failure', 'pending'
        timestamp: new Date().toISOString()
    };

    this.info(`Auditoría: ${action}`, auditData);
};

/**
 * Registrar actividad sospechosa
 * @param {Object} params - Parámetros de la actividad
 */
logger.logSuspiciousActivity = function(params) {
    const { reason, ip, userId, requestData, threshold } = params;

    const suspiciousData = {
        event: 'SUSPICIOUS_ACTIVITY',
        reason,
        ip,
        userId,
        requestData,
        threshold,
        timestamp: new Date().toISOString()
    };

    this.warn(`🔍 Actividad sospechosa: ${reason}`, suspiciousData);
};

/**
 * Registrar bloqueo de cuenta
 * @param {Object} params - Parámetros del bloqueo
 */
logger.logAccountLock = function(params) {
    const { userId, username, reason, duration, ip } = params;

    const lockData = {
        event: 'ACCOUNT_LOCKED',
        userId,
        username,
        reason,
        duration,
        ip,
        timestamp: new Date().toISOString()
    };

    this.warn(`🔒 Cuenta bloqueada: ${username}`, lockData);
};

/**
 * Registrar registro de usuario
 * @param {Object} params - Parámetros del registro
 */
logger.logUserRegistration = function(params) {
    const { userId, username, email, ip, userAgent, biometricEnabled } = params;

    const regData = {
        event: 'USER_REGISTRATION',
        userId,
        username,
        email,
        ip,
        userAgent,
        biometricEnabled,
        timestamp: new Date().toISOString()
    };

    this.info(`✅ Nuevo usuario registrado: ${username}`, regData);
};

/**
 * Registrar registro de credencial biométrica
 * @param {Object} params - Parámetros del registro
 */
logger.logBiometricRegistration = function(params) {
    const { userId, username, deviceType, credentialId, ip } = params;

    const bioData = {
        event: 'BIOMETRIC_REGISTRATION',
        userId,
        username,
        deviceType,
        credentialId: credentialId.substring(0, 20) + '...', // Truncar por seguridad
        ip,
        timestamp: new Date().toISOString()
    };

    this.info(`🔐 Credencial biométrica registrada para: ${username}`, bioData);
};

/**
 * Registrar uso de credencial biométrica
 * @param {Object} params - Parámetros del uso
 */
logger.logBiometricUsage = function(params) {
    const { userId, username, success, deviceType, ip } = params;

    const bioUsageData = {
        event: 'BIOMETRIC_AUTH',
        userId,
        username,
        success,
        deviceType,
        ip,
        timestamp: new Date().toISOString()
    };

    if (success) {
        this.info(`👆 Autenticación biométrica exitosa: ${username}`, bioUsageData);
    } else {
        this.warn(`👆 Autenticación biométrica fallida: ${username}`, bioUsageData);
    }
};

/**
 * Registrar cierre de sesión
 * @param {Object} params - Parámetros del logout
 */
logger.logLogout = function(params) {
    const { userId, username, ip, reason = 'user_initiated' } = params;

    const logoutData = {
        event: 'LOGOUT',
        userId,
        username,
        reason,
        ip,
        timestamp: new Date().toISOString()
    };

    this.info(`👋 Cierre de sesión: ${username}`, logoutData);
};

/**
 * Registrar intento de acceso no autorizado
 * @param {Object} params - Parámetros del intento
 */
logger.logUnauthorizedAccess = function(params) {
    const { resource, ip, userId, userAgent, reason } = params;

    const unauthData = {
        event: 'UNAUTHORIZED_ACCESS',
        resource,
        ip,
        userId,
        userAgent,
        reason,
        timestamp: new Date().toISOString()
    };

    this.warn(`🚫 Acceso no autorizado a: ${resource}`, unauthData);
};

module.exports = logger;
