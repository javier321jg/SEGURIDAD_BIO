# Secure Web App

Aplicación web con **SEGURIDAD EXTREMA** que implementa autenticación biométrica usando WebAuthn (Face ID, Touch ID, Windows Hello, huella dactilar) y múltiples capas de protección.

## Características de Seguridad

### Autenticación Biométrica (WebAuthn)
- Face ID (iOS/macOS)
- Touch ID (iOS/macOS)
- Windows Hello (Windows)
- Huella dactilar (Android)
- Llaves de seguridad USB (YubiKey)

### Headers de Seguridad (Helmet.js)
- Content-Security-Policy estricto
- X-Frame-Options: DENY (previene clickjacking)
- X-Content-Type-Options: nosniff
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### Protección contra Ataques
- **Rate Limiting**: Máximo 5 intentos por minuto
- **Protección CSRF**: Tokens únicos por sesión
- **Sanitización de Inputs**: Prevención XSS
- **Protección SQL Injection**: Consultas parametrizadas
- **Bloqueo de Cuenta**: Después de 5 intentos fallidos

### Sesiones Seguras
- **JWT**: Tokens con expiración corta (15 minutos)
- **Refresh Tokens**: Rotación automática
- **Cookies**: HttpOnly, Secure, SameSite=Strict
- **Renovación Automática**: Sin interrumpir al usuario

### Encriptación
- **Bcrypt**: Hash de contraseñas con 12 salt rounds
- **HTTPS**: Recomendado en producción
- **Datos Sensibles**: Almacenados de forma segura

### Logging y Monitoreo
- Registro de intentos de login (exitosos y fallidos)
- Alertas de actividad sospechosa
- Logs de auditoría completos
- Detección de ataques de fuerza bruta

## Estructura del Proyecto

```
secure-web-app/
├── backend/
│   ├── server.js              # Servidor Express principal
│   ├── package.json           # Dependencias del proyecto
│   ├── middleware/
│   │   └── security.js        # Middleware de seguridad
│   ├── routes/
│   │   └── auth.js            # Rutas de autenticación
│   └── utils/
│       ├── webauthn.js        # Utilidades WebAuthn
│       └── logger.js          # Sistema de logging
├── frontend/
│   ├── index.html             # Página de login
│   ├── register.html          # Página de registro
│   ├── dashboard.html         # Dashboard protegido
│   ├── css/
│   │   └── styles.css         # Estilos (modo oscuro, responsive)
│   └── js/
│       └── auth.js            # JavaScript de autenticación
├── .env.example               # Variables de entorno de ejemplo
└── README.md                  # Este archivo
```

## Requisitos

- Node.js >= 18.0.0
- npm o yarn
- Navegador moderno con soporte WebAuthn

## Instalación

1. **Clonar el repositorio**
```bash
git clone <url-del-repositorio>
cd secure-web-app
```

2. **Instalar dependencias**
```bash
cd backend
npm install
```

3. **Configurar variables de entorno**
```bash
cp .env.example .env
# Editar .env con tus valores
```

4. **Iniciar el servidor**
```bash
# Desarrollo
npm run dev

# Producción
npm start
```

5. **Abrir en el navegador**
```
http://localhost:3000
```

## Uso

### Registro de Usuario
1. Ir a `/register`
2. Completar el formulario con usuario, email y contraseña
3. La contraseña debe cumplir los requisitos de seguridad:
   - Mínimo 8 caracteres
   - Una letra mayúscula
   - Una letra minúscula
   - Un número
   - Un carácter especial (@$!%*?&)
4. Opcionalmente, configurar autenticación biométrica

### Login con Contraseña
1. Ir a `/` o `/login`
2. Ingresar usuario/email y contraseña
3. Después de 5 intentos fallidos, la cuenta se bloquea por 15 minutos

### Login con Biometría
1. Ingresar nombre de usuario
2. Hacer clic en "Usar Biometría"
3. Autenticarse con Face ID, Touch ID, huella, etc.

### Dashboard
- Ver estado de seguridad
- Gestionar dispositivos biométricos
- Cerrar sesión

## API Endpoints

### Autenticación
| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/auth/register` | Registrar nuevo usuario |
| POST | `/api/auth/login` | Login con contraseña |
| POST | `/api/auth/logout` | Cerrar sesión |
| POST | `/api/auth/refresh` | Renovar access token |
| GET | `/api/auth/me` | Obtener usuario actual |

### WebAuthn
| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/auth/webauthn/register/options` | Opciones de registro biométrico |
| POST | `/api/auth/webauthn/register/verify` | Verificar registro biométrico |
| POST | `/api/auth/webauthn/login/options` | Opciones de login biométrico |
| POST | `/api/auth/webauthn/login/verify` | Verificar login biométrico |

### Utilidades
| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/health` | Estado del servidor |
| GET | `/api/csrf-token` | Obtener token CSRF |

## Compatibilidad

### Navegadores
- Chrome 67+
- Safari 14+
- Firefox 60+
- Edge 79+

### Dispositivos Móviles
- iOS 14.5+ (Safari)
- Android 7+ (Chrome)

### Autenticadores Soportados
- Face ID (iPhone X+)
- Touch ID (iPhone 5s+, MacBook Pro)
- Windows Hello (Windows 10+)
- Huella dactilar Android
- Llaves USB (YubiKey, Titan)

## Configuración de Producción

### 1. Variables de Entorno
```bash
NODE_ENV=production
JWT_SECRET=<clave-segura-de-64-caracteres>
COOKIE_SECRET=<otra-clave-segura>
RP_ID=tu-dominio.com
ORIGIN=https://tu-dominio.com
```

### 2. HTTPS (Obligatorio para WebAuthn)
WebAuthn solo funciona en contextos seguros (HTTPS o localhost).

### 3. Base de Datos
Para producción, considera migrar a PostgreSQL:
```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

### 4. Rate Limiting
Ajustar límites según tus necesidades en `middleware/security.js`

## Seguridad Adicional

### Recomendaciones
1. **Usar HTTPS** en producción
2. **Cambiar secretos** (JWT_SECRET, COOKIE_SECRET)
3. **Configurar firewall** para limitar acceso
4. **Monitorear logs** regularmente
5. **Actualizar dependencias** periódicamente
6. **Backup** de base de datos

### Auditoría de Seguridad
Los logs se almacenan en `backend/logs/`:
- `error.log` - Errores
- `security.log` - Eventos de seguridad
- `audit.log` - Auditoría completa
- `combined.log` - Todos los logs

## Tecnologías

- **Backend**: Node.js, Express
- **Base de Datos**: SQLite (better-sqlite3)
- **Autenticación**: @simplewebauthn/server, JWT, bcrypt
- **Seguridad**: Helmet.js, express-rate-limit, xss
- **Frontend**: HTML5, CSS3, JavaScript vanilla
- **WebAuthn**: @simplewebauthn/browser

## Licencia

MIT License

## Contribuir

1. Fork el repositorio
2. Crear rama de feature (`git checkout -b feature/nueva-caracteristica`)
3. Commit cambios (`git commit -m 'Agregar nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Abrir Pull Request
