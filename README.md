# Login2FA
# Especificación de Requisitos de Software (SRS)

## 1. Introducción

### 1.1 Propósito
Este documento define los requisitos funcionales y no funcionales del sistema de inicio de sesión para una aplicación de redes sociales similar a Instagram. El sistema permitirá a los usuarios autenticarse de manera segura utilizando su nombre de usuario y contraseña.

### 1.2 Alcance
El sistema de login incluirá la autenticación de usuarios registrados, la recuperación de contraseña, el manejo de errores por credenciales inválidas y la integración con servicios de sesión y cookies.

### 1.3 Definiciones, acrónimos y abreviaturas
- **SRS**: Software Requirements Specification
- **UI**: Interfaz de Usuario
- **2FA**: Autenticación de dos factores

---

## 2. Descripción general

### 2.1 Perspectiva del producto
Este módulo es parte de una aplicación mayor similar a Instagram. Se integrará con módulos de registro de usuario, recuperación de cuenta y gestión de sesiones.

### 2.2 Funciones del producto
- Permitir a los usuarios autenticarse con nombre de usuario y contraseña.
- Notificar errores de login por credenciales inválidas.
- Soportar recuperación de contraseña mediante email.
- Registrar intentos fallidos.

### 2.3 Características del usuario
Usuarios finales sin conocimientos técnicos. Debe ser fácil de usar e intuitivo.

### 2.4 Restricciones
- El sistema debe estar disponible 24/7.
- Debe cumplir con normas de seguridad estándar.
- Tiempo máximo de respuesta: 2 segundos por solicitud.

---

## 3. Requisitos específicos

### 3.1 Requisitos funcionales

#### RF1 - Inicio de sesión
El sistema debe permitir a los usuarios iniciar sesión introduciendo su nombre de usuario y contraseña.

#### RF2 - Validación de credenciales
El sistema debe validar que las credenciales ingresadas coincidan con las almacenadas en la base de datos.

#### RF3 - Recuperación de contraseña
El sistema debe permitir recuperar la contraseña mediante un correo electrónico con un enlace seguro.

#### RF4 - Gestión de sesión
El sistema debe iniciar una sesión de usuario tras el login exitoso y mantenerla activa durante el uso.

#### RF5 - Manejo de errores
El sistema debe informar de forma clara si los datos ingresados son incorrectos o si hay un error del servidor.

### 3.2 Requisitos no funcionales

#### RNF1 - Seguridad
Todas las contraseñas deben almacenarse cifradas con bcrypt o similar. Las comunicaciones deben usar HTTPS.

#### RNF2 - Usabilidad
El formulario de login debe ser simple y estar adaptado a dispositivos móviles.

#### RNF3 - Rendimiento
El sistema debe responder en menos de 2 segundos para el 95% de las solicitudes.

#### RNF4 - Compatibilidad
Debe funcionar en los navegadores modernos: Chrome, Firefox, Edge, Safari.

---

## 4. Apéndices
- Prototipo UI (no incluido en este documento).
- Referencia: OWASP Authentication Guidelines.

