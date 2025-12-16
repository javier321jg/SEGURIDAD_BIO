/**
 * =============================================================================
 * SERVIDOR PRINCIPAL - APLICACIÓN WEB SEGURA
 * =============================================================================
 *
 * Este servidor implementa múltiples capas de seguridad:
 * - Autenticación biométrica con WebAuthn (Face ID, Touch ID, Windows Hello)
 * - Headers de seguridad con Helmet.js
 * - Protección CSRF, XSS, SQL Injection
 * - Rate limiting para prevenir ataques de fuerza bruta
 * - JWT con tokens de corta duración
 * - Logging completo de auditoría
 *
 * Compatible con dispositivos móviles (Android/iOS)
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');

// Importar middleware de seguridad personalizado
const securityMiddleware = require('./middleware/security');

// Importar rutas
const authRoutes = require('./routes/auth');

// Importar logger de auditoría
const logger = require('./utils/logger');

// =============================================================================
// CONFIGURACIÓN DEL SERVIDOR
// =============================================================================

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Configuración de la base de datos SQLite
const db = new Database('./database.sqlite', { verbose: console.log });

// Inicializar tablas de la base de datos
initializeDatabase();

// =============================================================================
// MIDDLEWARE DE SEGURIDAD GLOBAL
// =============================================================================

// 1. HELMET - Headers de seguridad HTTP
app.use(helmet({
    // Content Security Policy estricto
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Para compatibilidad móvil
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
        },
    },
    // X-Frame-Options: Prevenir clickjacking
    frameguard: { action: 'deny' },
    // X-Content-Type-Options: Prevenir MIME sniffing
    noSniff: true,
    // Strict-Transport-Security: Forzar HTTPS
    hsts: {
        maxAge: 31536000, // 1 año
        includeSubDomains: true,
        preload: true
    },
    // X-XSS-Protection
    xssFilter: true,
    // Referrer-Policy
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // X-Permitted-Cross-Domain-Policies
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    // X-Download-Options (IE)
    ieNoOpen: true,
    // X-DNS-Prefetch-Control
    dnsPrefetchControl: { allow: false }
}));

// 2. CORS - Configuración restrictiva
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS ?
        process.env.ALLOWED_ORIGINS.split(',') :
        ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true, // Permitir cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-CSRF-Token'],
    maxAge: 600 // Cache preflight por 10 minutos
};
app.use(cors(corsOptions));

// 3. Parsers de body y cookies
app.use(express.json({ limit: '10kb' })); // Limitar tamaño del body
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'super-secret-cookie-key'));

// 4. Aplicar middleware de seguridad personalizado
app.use(securityMiddleware.rateLimiter);
app.use(securityMiddleware.sanitizeInput);
app.use(securityMiddleware.requestLogger);

// 5. Generar y verificar tokens CSRF
app.use(securityMiddleware.csrfProtection);

// =============================================================================
// RUTAS ESTÁTICAS (FRONTEND)
// =============================================================================

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, '../frontend'), {
    // Headers de seguridad para archivos estáticos
    setHeaders: (res, filePath) => {
        // Cache control para archivos estáticos
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        } else if (filePath.match(/\.(css|js)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 año
        }
    }
}));

// =============================================================================
// RUTAS DE LA API
// =============================================================================

// Endpoint de salud del servidor
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        security: 'enabled'
    });
});

// Endpoint para obtener token CSRF
app.get('/api/csrf-token', (req, res) => {
    const csrfToken = req.csrfToken || uuidv4();

    // Guardar token en sesión/cookie
    res.cookie('csrf-token', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutos
    });

    res.json({ csrfToken });
});

// Rutas de autenticación
app.use('/api/auth', authRoutes);

// =============================================================================
// RUTAS DE PÁGINAS
// =============================================================================

// Página de login
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Página de registro
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/register.html'));
});

// Dashboard (requiere autenticación - verificado en frontend)
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/dashboard.html'));
});

// =============================================================================
// MANEJO DE ERRORES
// =============================================================================

// Middleware para rutas no encontradas
app.use((req, res, next) => {
    logger.warn(`Ruta no encontrada: ${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    res.status(404).json({
        error: 'Recurso no encontrado',
        code: 'NOT_FOUND'
    });
});

// Middleware de manejo de errores global
app.use((err, req, res, next) => {
    // Log del error
    logger.error('Error en el servidor:', {
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip
    });

    // Errores de CSRF
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({
            error: 'Token CSRF inválido o expirado',
            code: 'CSRF_ERROR'
        });
    }

    // Errores de rate limiting
    if (err.status === 429) {
        return res.status(429).json({
            error: 'Demasiadas solicitudes. Por favor, espera antes de intentar de nuevo.',
            code: 'RATE_LIMIT_EXCEEDED'
        });
    }

    // Error genérico (no exponer detalles en producción)
    const statusCode = err.status || 500;
    res.status(statusCode).json({
        error: process.env.NODE_ENV === 'production'
            ? 'Error interno del servidor'
            : err.message,
        code: 'INTERNAL_ERROR'
    });
});

// =============================================================================
// INICIALIZACIÓN DE BASE DE DATOS
// =============================================================================

function initializeDatabase() {
    console.log('🔧 Inicializando base de datos...');

    // Tabla de usuarios
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until DATETIME NULL
        )
    `);

    // Tabla de credenciales WebAuthn (biometría)
    db.exec(`
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            credential_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            counter INTEGER DEFAULT 0,
            device_type TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Tabla de tokens de refresh
    db.exec(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Tabla de desafíos WebAuthn (temporal)
    db.exec(`
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            challenge TEXT NOT NULL,
            type TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Tabla de logs de auditoría
    db.exec(`
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            status TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Tabla de alertas de seguridad
    db.exec(`
        CREATE TABLE IF NOT EXISTS security_alerts (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            ip_address TEXT,
            user_id TEXT,
            resolved INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Índices para optimización
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
        CREATE INDEX IF NOT EXISTS idx_alerts_type ON security_alerts(type);
    `);

    console.log('✅ Base de datos inicializada correctamente');
}

// Exportar base de datos para uso en otros módulos
module.exports.db = db;

// =============================================================================
// INICIAR SERVIDOR
// =============================================================================

// Limpiar desafíos expirados periódicamente
setInterval(() => {
    const stmt = db.prepare('DELETE FROM webauthn_challenges WHERE expires_at < datetime("now")');
    stmt.run();
}, 60000); // Cada minuto

// Limpiar tokens de refresh expirados
setInterval(() => {
    const stmt = db.prepare('DELETE FROM refresh_tokens WHERE expires_at < datetime("now")');
    stmt.run();
}, 3600000); // Cada hora

// Iniciar servidor
app.listen(PORT, HOST, () => {
    console.log('');
    console.log('🔐 ═══════════════════════════════════════════════════════════');
    console.log('🔐  SERVIDOR WEB SEGURO INICIADO');
    console.log('🔐 ═══════════════════════════════════════════════════════════');
    console.log(`🔐  URL: http://${HOST}:${PORT}`);
    console.log(`🔐  Entorno: ${process.env.NODE_ENV || 'development'}`);
    console.log('🔐  Características de seguridad activas:');
    console.log('🔐    ✓ Helmet.js (Headers de seguridad)');
    console.log('🔐    ✓ Rate Limiting (5 intentos/minuto)');
    console.log('🔐    ✓ Protección CSRF');
    console.log('🔐    ✓ Sanitización de inputs');
    console.log('🔐    ✓ WebAuthn (Autenticación biométrica)');
    console.log('🔐    ✓ JWT con tokens cortos (15 min)');
    console.log('🔐    ✓ Cookies HttpOnly + Secure + SameSite');
    console.log('🔐    ✓ Logging de auditoría');
    console.log('🔐 ═══════════════════════════════════════════════════════════');
    console.log('');

    logger.info('Servidor iniciado', { port: PORT, host: HOST });
});

// Manejo de señales de terminación
process.on('SIGTERM', () => {
    console.log('🔐 Cerrando servidor de forma segura...');
    db.close();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🔐 Cerrando servidor de forma segura...');
    db.close();
    process.exit(0);
});
