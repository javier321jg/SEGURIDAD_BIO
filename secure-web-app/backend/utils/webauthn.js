/**
 * =============================================================================
 * UTILIDADES WEBAUTHN - AUTENTICACIÓN BIOMÉTRICA
 * =============================================================================
 *
 * Este módulo implementa la autenticación biométrica usando WebAuthn:
 * - Face ID (iOS/macOS)
 * - Touch ID (iOS/macOS)
 * - Windows Hello (Windows)
 * - Huella dactilar (Android)
 * - Llaves de seguridad USB (YubiKey, etc.)
 *
 * Compatible con dispositivos móviles (Android/iOS)
 */

const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const { v4: uuidv4 } = require('uuid');
const logger = require('./logger');

// =============================================================================
// CONFIGURACIÓN
// =============================================================================

// Configuración del Relying Party (tu aplicación)
const rpConfig = {
    // Nombre visible para el usuario
    rpName: process.env.RP_NAME || 'Secure Web App',
    // ID del dominio (debe coincidir con el dominio donde se ejecuta)
    rpID: process.env.RP_ID || 'localhost',
    // Origen permitido
    origin: process.env.ORIGIN || 'http://localhost:3000'
};

// =============================================================================
// GENERACIÓN DE OPCIONES DE REGISTRO
// =============================================================================

/**
 * Genera las opciones para registrar una nueva credencial biométrica
 *
 * @param {Object} user - Usuario que registra la credencial
 * @param {Array} existingCredentials - Credenciales existentes del usuario
 * @returns {Object} Opciones de registro para el cliente
 */
async function generateRegistrationOptionsForUser(user, existingCredentials = []) {
    try {
        // Convertir credenciales existentes al formato requerido
        const excludeCredentials = existingCredentials.map(cred => ({
            id: Buffer.from(cred.credential_id, 'base64url'),
            type: 'public-key',
            transports: ['internal', 'hybrid', 'usb', 'ble', 'nfc']
        }));

        const options = await generateRegistrationOptions({
            rpName: rpConfig.rpName,
            rpID: rpConfig.rpID,
            userID: user.id,
            userName: user.username,
            userDisplayName: user.username,

            // Tiempo de espera: 60 segundos
            timeout: 60000,

            // Tipo de attestation (para dispositivos móviles, usar 'none' o 'indirect')
            attestationType: 'none',

            // Excluir credenciales ya registradas
            excludeCredentials,

            // Algoritmos soportados (ES256 y RS256)
            supportedAlgorithmIDs: [-7, -257],

            // Criterios del autenticador
            authenticatorSelection: {
                // Preferir autenticadores de plataforma (Face ID, Touch ID, Windows Hello)
                authenticatorAttachment: 'platform',
                // Requerir verificación del usuario (biometría o PIN)
                userVerification: 'required',
                // Permitir credenciales descubribles (Passkeys)
                residentKey: 'preferred',
                requireResidentKey: false
            }
        });

        logger.info('Opciones de registro WebAuthn generadas', {
            userId: user.id,
            username: user.username,
            challengeLength: options.challenge.length
        });

        return {
            success: true,
            options
        };
    } catch (error) {
        logger.error('Error generando opciones de registro WebAuthn', {
            error: error.message,
            userId: user.id
        });

        return {
            success: false,
            error: error.message
        };
    }
}

// =============================================================================
// VERIFICACIÓN DE REGISTRO
// =============================================================================

/**
 * Verifica la respuesta de registro del cliente
 *
 * @param {Object} response - Respuesta del cliente
 * @param {string} expectedChallenge - Desafío esperado
 * @returns {Object} Resultado de la verificación
 */
async function verifyRegistration(response, expectedChallenge) {
    try {
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge,
            expectedOrigin: rpConfig.origin,
            expectedRPID: rpConfig.rpID,
            requireUserVerification: true
        });

        if (verification.verified && verification.registrationInfo) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

            logger.info('Registro WebAuthn verificado exitosamente', {
                credentialId: Buffer.from(credentialID).toString('base64url').substring(0, 20)
            });

            return {
                success: true,
                verified: true,
                credential: {
                    credentialId: Buffer.from(credentialID).toString('base64url'),
                    publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
                    counter
                }
            };
        }

        return {
            success: true,
            verified: false,
            error: 'Verificación fallida'
        };
    } catch (error) {
        logger.error('Error verificando registro WebAuthn', {
            error: error.message
        });

        return {
            success: false,
            verified: false,
            error: error.message
        };
    }
}

// =============================================================================
// GENERACIÓN DE OPCIONES DE AUTENTICACIÓN
// =============================================================================

/**
 * Genera las opciones para autenticar con biometría
 *
 * @param {Array} userCredentials - Credenciales del usuario
 * @returns {Object} Opciones de autenticación para el cliente
 */
async function generateAuthenticationOptionsForUser(userCredentials = []) {
    try {
        // Convertir credenciales al formato requerido
        const allowCredentials = userCredentials.map(cred => ({
            id: Buffer.from(cred.credential_id, 'base64url'),
            type: 'public-key',
            transports: ['internal', 'hybrid', 'usb', 'ble', 'nfc']
        }));

        const options = await generateAuthenticationOptions({
            rpID: rpConfig.rpID,
            timeout: 60000,
            allowCredentials,
            userVerification: 'required'
        });

        logger.info('Opciones de autenticación WebAuthn generadas', {
            credentialsCount: userCredentials.length,
            challengeLength: options.challenge.length
        });

        return {
            success: true,
            options
        };
    } catch (error) {
        logger.error('Error generando opciones de autenticación WebAuthn', {
            error: error.message
        });

        return {
            success: false,
            error: error.message
        };
    }
}

// =============================================================================
// VERIFICACIÓN DE AUTENTICACIÓN
// =============================================================================

/**
 * Verifica la respuesta de autenticación del cliente
 *
 * @param {Object} response - Respuesta del cliente
 * @param {string} expectedChallenge - Desafío esperado
 * @param {Object} credential - Credencial almacenada
 * @returns {Object} Resultado de la verificación
 */
async function verifyAuthentication(response, expectedChallenge, credential) {
    try {
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin: rpConfig.origin,
            expectedRPID: rpConfig.rpID,
            authenticator: {
                credentialID: Buffer.from(credential.credential_id, 'base64url'),
                credentialPublicKey: Buffer.from(credential.public_key, 'base64url'),
                counter: credential.counter
            },
            requireUserVerification: true
        });

        if (verification.verified) {
            logger.info('Autenticación WebAuthn verificada exitosamente', {
                credentialId: credential.credential_id.substring(0, 20),
                newCounter: verification.authenticationInfo.newCounter
            });

            return {
                success: true,
                verified: true,
                newCounter: verification.authenticationInfo.newCounter
            };
        }

        return {
            success: true,
            verified: false,
            error: 'Verificación fallida'
        };
    } catch (error) {
        logger.error('Error verificando autenticación WebAuthn', {
            error: error.message
        });

        return {
            success: false,
            verified: false,
            error: error.message
        };
    }
}

// =============================================================================
// UTILIDADES
// =============================================================================

/**
 * Detecta el tipo de dispositivo basado en el user agent
 *
 * @param {string} userAgent - User agent del navegador
 * @returns {string} Tipo de dispositivo
 */
function detectDeviceType(userAgent) {
    const ua = userAgent.toLowerCase();

    if (ua.includes('iphone') || ua.includes('ipad')) {
        return 'iOS (Face ID / Touch ID)';
    } else if (ua.includes('android')) {
        return 'Android (Huella / Face)';
    } else if (ua.includes('windows')) {
        return 'Windows Hello';
    } else if (ua.includes('mac')) {
        return 'macOS (Touch ID)';
    } else if (ua.includes('linux')) {
        return 'Linux';
    }

    return 'Desconocido';
}

/**
 * Genera un desafío único
 *
 * @returns {string} Desafío en base64url
 */
function generateChallenge() {
    const buffer = new Uint8Array(32);
    require('crypto').randomFillSync(buffer);
    return Buffer.from(buffer).toString('base64url');
}

/**
 * Verifica si WebAuthn está soportado en el cliente
 * (Esta función es para referencia, la verificación real se hace en el frontend)
 *
 * @returns {Object} Información sobre soporte WebAuthn
 */
function getWebAuthnSupport() {
    return {
        message: 'La verificación de soporte WebAuthn debe hacerse en el cliente',
        clientCode: `
            // Código para verificar en el cliente:
            const isSupported = window.PublicKeyCredential !== undefined;
            const isPlatformAuthenticatorAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        `
    };
}

// =============================================================================
// EXPORTAR FUNCIONES
// =============================================================================

module.exports = {
    rpConfig,
    generateRegistrationOptionsForUser,
    verifyRegistration,
    generateAuthenticationOptionsForUser,
    verifyAuthentication,
    detectDeviceType,
    generateChallenge,
    getWebAuthnSupport
};
