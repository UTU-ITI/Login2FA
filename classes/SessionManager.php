<?php
// classes/SessionManager.php

class SessionManager {
    private PDO $db;
    
    public function __construct(PDO $db) {
        $this->db = $db;
        $this->configureSession();
    }
    
    private function configureSession(): void {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', '1');
        
        session_name(SESSION_NAME);
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }
    
    public function start(): bool {
        if (session_status() === PHP_SESSION_NONE) {
            if (session_start()) {
                if (!$this->validateSession()) {
                    $this->destroy();
                    return false;
                }
                $this->regenerateIfNeeded();
                return true;
            }
        }
        return session_status() === PHP_SESSION_ACTIVE;
    }
    
    private function validateSession(): bool {
        // Validar IP
        if (!isset($_SESSION['ip_address'])) {
            $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        } elseif ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
            return false;
        }
        
        // Validar User-Agent
        if (!isset($_SESSION['user_agent'])) {
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        } elseif ($_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
            return false;
        }
        
        // Validar timeout
        if (isset($_SESSION['last_activity'])) {
            if (time() - $_SESSION['last_activity'] > SESSION_LIFETIME) {
                return false;
            }
        }
        $_SESSION['last_activity'] = time();
        
        return true;
    }
    
    private function regenerateIfNeeded(): void {
        if (!isset($_SESSION['created_at'])) {
            $_SESSION['created_at'] = time();
        } elseif (time() - $_SESSION['created_at'] > 300) { // Cada 5 minutos
            session_regenerate_id(true);
            $_SESSION['created_at'] = time();
        }
    }
    
    public function login(int $userId, string $username, string $rol): void {
        session_regenerate_id(true);
        
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        $_SESSION['rol'] = $rol;
        $_SESSION['logged_in'] = true;
        $_SESSION['created_at'] = time();
        $_SESSION['last_activity'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Guardar sesión en BD
        $this->saveSessionToDB($userId);
    }
    
    private function saveSessionToDB(int $userId): void {
        $stmt = $this->db->prepare("
            INSERT INTO sesiones (id, usuario_id, ip_address, user_agent, datos_sesion)
            VALUES (:id, :usuario_id, :ip, :user_agent, :datos)
            ON DUPLICATE KEY UPDATE 
                ultima_actividad = CURRENT_TIMESTAMP,
                datos_sesion = :datos
        ");
        
        $stmt->execute([
            'id' => session_id(),
            'usuario_id' => $userId,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'datos' => json_encode($_SESSION)
        ]);
    }
    
    public function logout(): void {
        if (isset($_SESSION['user_id'])) {
            // Eliminar sesión de BD
            $stmt = $this->db->prepare("DELETE FROM sesiones WHERE id = :id");
            $stmt->execute(['id' => session_id()]);
            
            // Log de logout
            $this->logEvent($_SESSION['user_id'], 'logout');
        }
        
        $this->destroy();
    }
    
    public function destroy(): void {
        $_SESSION = [];
        
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }
        
        session_destroy();
    }
    
    public function isLoggedIn(): bool {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }
    
    public function getUserId(): ?int {
        return $_SESSION['user_id'] ?? null;
    }
    
    public function getUsername(): ?string {
        return $_SESSION['username'] ?? null;
    }
    
    public function getRol(): ?string {
        return $_SESSION['rol'] ?? null;
    }
    
    public function require2FA(): void {
        $_SESSION['requires_2fa'] = true;
        $_SESSION['2fa_verified'] = false;
    }
    
    public function verify2FA(): void {
        $_SESSION['2fa_verified'] = true;
        unset($_SESSION['requires_2fa']);
    }
    
    public function is2FAVerified(): bool {
        return !isset($_SESSION['requires_2fa']) || 
               (isset($_SESSION['2fa_verified']) && $_SESSION['2fa_verified']);
    }
    
    public function cleanExpiredSessions(): void {
        $stmt = $this->db->prepare("
            DELETE FROM sesiones 
            WHERE ultima_actividad < DATE_SUB(NOW(), INTERVAL :lifetime SECOND)
        ");
        $stmt->execute(['lifetime' => SESSION_LIFETIME]);
    }
    
    private function logEvent(int $userId, string $tipo): void {
        $stmt = $this->db->prepare("
            INSERT INTO logs_autenticacion 
            (usuario_id, tipo_evento, ip_address, user_agent)
            VALUES (:usuario_id, :tipo, :ip, :user_agent)
        ");
        
        $stmt->execute([
            'usuario_id' => $userId,
            'tipo' => $tipo,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }
}