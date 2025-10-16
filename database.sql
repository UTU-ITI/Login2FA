-- Tabla de usuarios
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255), -- NULL para usuarios con OAuth (GitHub)
    rol ENUM('Estudiante', 'Asistente', 'Docente', 'Administrativo', 'SysAdmin') NOT NULL,
    secret_2fa VARCHAR(255), -- Solo para SysAdmin
    github_id VARCHAR(100), -- Solo para Estudiantes
    debe_cambiar_password BOOLEAN DEFAULT FALSE,
    ultima_modificacion_password DATETIME,
    intentos_fallidos INT DEFAULT 0,
    bloqueado_hasta DATETIME,
    activo BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_github_id (github_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de historial de contraseñas (para evitar reutilización)
CREATE TABLE historial_passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_usuario_id (usuario_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de sesiones
CREATE TABLE sesiones (
    id VARCHAR(64) PRIMARY KEY,
    usuario_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255),
    ultima_actividad TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    datos_sesion TEXT,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_usuario_id (usuario_id),
    INDEX idx_ultima_actividad (ultima_actividad)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de logs de autenticación
CREATE TABLE logs_autenticacion (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    username VARCHAR(100),
    tipo_evento ENUM('login_exitoso', 'login_fallido', '2fa_exitoso', '2fa_fallido', 'logout', 'password_cambiado') NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    detalles TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_usuario_id (usuario_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Datos de ejemplo
INSERT INTO usuarios (username, email, password, rol, debe_cambiar_password) VALUES
('admin.user', 'admin@example.com', '$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyJ3H/XWXS3q', 'Administrativo', TRUE),
('asistente1', 'asistente@example.com', '$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyJ3H/XWXS3q', 'Asistente', TRUE),
('docente1', 'docente@example.com', '$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyJ3H/XWXS3q', 'Docente', FALSE),
('sysadmin', 'sysadmin@example.com', '$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyJ3H/XWXS3q', 'SysAdmin', FALSE);

-- Nota: El password de ejemplo es 'Password123!' para todos