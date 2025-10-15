<?php
// classes/TwoFactorAuth.php

class TwoFactorAuth {
    private PDO $db;
    
    public function __construct(PDO $db) {
        $this->db = $db;
    }
    
    /**
     * Genera un secreto base32 para TOTP
     */
    public function generateSecret(): string {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < 32; $i++) {
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $secret;
    }
    
    /**
     * Habilita 2FA para un usuario
     */
    public function enable(int $userId): string {
        $secret = $this->generateSecret();
        
        $stmt = $this->db->prepare("
            UPDATE usuarios 
            SET secret_2fa = :secret 
            WHERE id = :id
        ");
        
        $stmt->execute([
            'secret' => $secret,
            'id' => $userId
        ]);
        
        return $secret;
    }
    
    /**
     * Deshabilita 2FA para un usuario
     */
    public function disable(int $userId): bool {
        $stmt = $this->db->prepare("
            UPDATE usuarios 
            SET secret_2fa = NULL 
            WHERE id = :id
        ");
        
        return $stmt->execute(['id' => $userId]);
    }
    
    /**
     * Verifica un código TOTP
     */
    public function verifyCode(string $secret, string $code, int $window = 1): bool {
        $currentTime = floor(time() / 30);
        
        // Verificar en ventana de tiempo (permite códigos pasados/futuros)
        for ($i = -$window; $i <= $window; $i++) {
            $testTime = $currentTime + $i;
            if ($this->generateCode($secret, $testTime) === $code) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Genera un código TOTP para un momento específico
     */
    private function generateCode(string $secret, int $timeSlice): string {
        $key = $this->base32Decode($secret);
        
        // Pack time slice como big-endian
        $time = pack('N*', 0) . pack('N*', $timeSlice);
        
        // HMAC-SHA1
        $hash = hash_hmac('sha1', $time, $key, true);
        
        // Dynamic truncation
        $offset = ord($hash[19]) & 0xf;
        $code = (
            ((ord($hash[$offset + 0]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;
        
        return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
    }
    
    /**
     * Decodifica Base32
     */
    private function base32Decode(string $secret): string {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = strtoupper($secret);
        $decoded = '';
        
        for ($i = 0; $i < strlen($secret); $i += 8) {
            $chunk = substr($secret, $i, 8);
            $bits = '';
            
            for ($j = 0; $j < strlen($chunk); $j++) {
                $val = strpos($chars, $chunk[$j]);
                if ($val === false) continue;
                $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
            }
            
            for ($j = 0; $j < strlen($bits); $j += 8) {
                $byte = substr($bits, $j, 8);
                if (strlen($byte) === 8) {
                    $decoded .= chr(bindec($byte));
                }
            }
        }
        
        return $decoded;
    }
    
    /**
     * Obtiene el secreto 2FA de un usuario
     */
    public function getSecret(int $userId): ?string {
        $stmt = $this->db->prepare("
            SELECT secret_2fa 
            FROM usuarios 
            WHERE id = :id
        ");
        
        $stmt->execute(['id' => $userId]);
        return $stmt->fetchColumn() ?: null;
    }
    
    /**
     * Verifica si un usuario tiene 2FA habilitado
     */
    public function isEnabled(int $userId): bool {
        return $this->getSecret($userId) !== null;
    }
    
    /**
     * Genera una URL para código QR (compatible con Google Authenticator)
     */
    public function getQRCodeUrl(string $secret, string $username, string $issuer = 'SistemaAuth'): string {
        $label = urlencode($issuer . ':' . $username);
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => 6,
            'period' => 30
        ]);
        
        return "otpauth://totp/{$label}?{$params}";
    }
    
    /**
     * Genera códigos de backup
     */
    public function generateBackupCodes(int $count = 10): array {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = bin2hex(random_bytes(4));
        }
        return $codes;
    }
    
    /**
     * Log de evento 2FA
     */
    public function logAttempt(int $userId, bool $success): void {
        $stmt = $this->db->prepare("
            INSERT INTO logs_autenticacion 
            (usuario_id, tipo_evento, ip_address, user_agent)
            VALUES (:usuario_id, :tipo, :ip, :user_agent)
        ");
        
        $stmt->execute([
            'usuario_id' => $userId,
            'tipo' => $success ? '2fa_exitoso' : '2fa_fallido',
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }
}