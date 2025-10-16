<?php
// tests/PasswordPolicyTest.php
use PHPUnit\Framework\TestCase;

class PasswordPolicyTest extends TestCase {
    private PDO $db;
    private PasswordPolicy $policy;
    
    protected function setUp(): void {
        // Usar base de datos de prueba
        $this->db = new PDO('mysql:host=localhost;dbname=test_sistema_autenticacion', 'root', '');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->policy = new PasswordPolicy($this->db);
        
        // Limpiar tablas
        $this->db->exec("TRUNCATE TABLE usuarios");
        $this->db->exec("TRUNCATE TABLE historial_passwords");
    }
    
    public function testValidatePasswordLength() {
        $errors = $this->policy->validate('Short1!');
        $this->assertContains('al menos 12 caracteres', implode(' ', $errors));
    }
    
    public function testValidatePasswordUppercase() {
        $errors = $this->policy->validate('nouppercas3!');
        $this->assertContains('mayúscula', implode(' ', $errors));
    }
    
    public function testValidatePasswordLowercase() {
        $errors = $this->policy->validate('NOLOWERCASE3!');
        $this->assertContains('minúscula', implode(' ', $errors));
    }
    
    public function testValidatePasswordNumber() {
        $errors = $this->policy->validate('NoNumbersHere!');
        $this->assertContains('número', implode(' ', $errors));
    }
    
    public function testValidatePasswordSpecial() {
        $errors = $this->policy->validate('NoSpecial123');
        $this->assertContains('especial', implode(' ', $errors));
    }
    
    public function testValidatePasswordCommonWords() {
        $errors = $this->policy->validate('Password123!');
        $this->assertContains('comunes', implode(' ', $errors));
    }
    
    public function testValidateValidPassword() {
        $errors = $this->policy->validate('MySecure@Pass123');
        $this->assertEmpty($errors);
    }
    
    public function testCheckHistoryNoHistory() {
        $userId = 1;
        $result = $this->policy->checkHistory($userId, 'NewPassword123!');
        $this->assertTrue($result);
    }
    
    public function testCheckHistoryWithReuse() {
        // Crear usuario
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, rol) VALUES (?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', 'Docente']);
        $userId = $this->db->lastInsertId();
        
        // Agregar password al historial
        $hash = password_hash('OldPassword123!', PASSWORD_ARGON2ID);
        $stmt = $this->db->prepare("INSERT INTO historial_passwords (usuario_id, password_hash) VALUES (?, ?)");
        $stmt->execute([$userId, $hash]);
        
        // Intentar reutilizar
        $result = $this->policy->checkHistory($userId, 'OldPassword123!');
        $this->assertFalse($result);
    }
    
    public function testIsExpiredNeverChanged() {
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, rol) VALUES (?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', 'Asistente']);
        $userId = $this->db->lastInsertId();
        
        $result = $this->policy->isExpired($userId);
        $this->assertTrue($result);
    }
    
    public function testIsExpiredRecent() {
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, rol, ultima_modificacion_password) VALUES (?, ?, ?, NOW())");
        $stmt->execute(['testuser', 'test@example.com', 'Asistente']);
        $userId = $this->db->lastInsertId();
        
        $result = $this->policy->isExpired($userId);
        $this->assertFalse($result);
    }
    
    public function testGenerateSecurePassword() {
        $password = $this->policy->generateSecurePassword(16);
        
        $this->assertEquals(16, strlen($password));
        $this->assertMatchesRegularExpression('/[A-Z]/', $password);
        $this->assertMatchesRegularExpression('/[a-z]/', $password);
        $this->assertMatchesRegularExpression('/[0-9]/', $password);
        $this->assertMatchesRegularExpression('/[^A-Za-z0-9]/', $password);
    }
}

// tests/TwoFactorAuthTest.php
class TwoFactorAuthTest extends TestCase {
    private PDO $db;
    private TwoFactorAuth $twoFA;
    
    protected function setUp(): void {
        $this->db = new PDO('mysql:host=localhost;dbname=test_sistema_autenticacion', 'root', '');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->twoFA = new TwoFactorAuth($this->db);
        
        $this->db->exec("TRUNCATE TABLE usuarios");
    }
    
    public function testGenerateSecret() {
        $secret = $this->twoFA->generateSecret();
        
        $this->assertEquals(32, strlen($secret));
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
    }
    
    public function testVerifyValidCode() {
        $secret = 'JBSWY3DPEHPK3PXP';
        $timeSlice = floor(time() / 30);
        
        // Generar código válido para el momento actual
        $reflection = new ReflectionClass($this->twoFA);
        $method = $reflection->getMethod('generateCode');
        $method->setAccessible(true);
        $code = $method->invoke($this->twoFA, $secret, $timeSlice);
        
        $result = $this->twoFA->verifyCode($secret, $code);
        $this->assertTrue($result);
    }
    
    public function testVerifyInvalidCode() {
        $secret = 'JBSWY3DPEHPK3PXP';
        $result = $this->twoFA->verifyCode($secret, '000000');
        $this->assertFalse($result);
    }
    
    public function testEnableAndDisable() {
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, rol) VALUES (?, ?, ?)");
        $stmt->execute(['testadmin', 'admin@example.com', 'SysAdmin']);
        $userId = $this->db->lastInsertId();
        
        // Habilitar
        $secret = $this->twoFA->enable($userId);
        $this->assertNotEmpty($secret);
        
        // Verificar que está habilitado
        $this->assertTrue($this->twoFA->isEnabled($userId));
        
        // Deshabilitar
        $this->twoFA->disable($userId);
        $this->assertFalse($this->twoFA->isEnabled($userId));
    }
    
    public function testGetQRCodeUrl() {
        $secret = 'JBSWY3DPEHPK3PXP';
        $username = 'testuser';
        $url = $this->twoFA->getQRCodeUrl($secret, $username);
        
        $this->assertStringContainsString('otpauth://totp/', $url);
        $this->assertStringContainsString($secret, $url);
        $this->assertStringContainsString($username, $url);
    }
    
    public function testGenerateBackupCodes() {
        $codes = $this->twoFA->generateBackupCodes(10);
        
        $this->assertCount(10, $codes);
        foreach ($codes as $code) {
            $this->assertEquals(8, strlen($code));
            $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $code);
        }
        
        // Verificar que son únicos
        $this->assertEquals(10, count(array_unique($codes)));
    }
}

// tests/SessionManagerTest.php
class SessionManagerTest extends TestCase {
    private PDO $db;
    private SessionManager $session;
    
    protected function setUp(): void {
        $this->db = new PDO('mysql:host=localhost;dbname=test_sistema_autenticacion', 'root', '');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->session = new SessionManager($this->db);
        
        $this->db->exec("TRUNCATE TABLE sesiones");
        $this->db->exec("TRUNCATE TABLE usuarios");
        
        // Simular entorno de servidor
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'PHPUnit Test';
    }
    
    protected function tearDown(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        $_SESSION = [];
    }
    
    public function testStart() {
        $result = $this->session->start();
        $this->assertTrue($result);
        $this->assertEquals(PHP_SESSION_ACTIVE, session_status());
    }
    
    public function testLogin() {
        $this->session->start();
        
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, rol) VALUES (?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', 'Docente']);
        $userId = $this->db->lastInsertId();
        
        $this->session->login($userId, 'testuser', 'Docente');
        
        $this->assertTrue($this->session->isLoggedIn());
        $this->assertEquals($userId, $this->session->getUserId());
        $this->assertEquals('testuser', $this->session->getUsername());
        $this->assertEquals('Docente', $this->session->getRol());
    }
    
    public function testLogout() {
        $this->session->start();
        
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, rol) VALUES (?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', 'Docente']);
        $userId = $this->db->lastInsertId();
        
        $this->session->login($userId, 'testuser', 'Docente');
        $this->assertTrue($this->session->isLoggedIn());
        
        $this->session->logout();
        $this->assertFalse($this->session->isLoggedIn());
    }
    
    public function test2FAFlow() {
        $this->session->start();
        
        $this->session->require2FA();
        $this->assertFalse($this->session->is2FAVerified());
        
        $this->session->verify2FA();
        $this->assertTrue($this->session->is2FAVerified());
    }
}

// tests/AuthManagerTest.php
class AuthManagerTest extends TestCase {
    private PDO $db;
    private AuthManager $auth;
    
    protected function setUp(): void {
        $this->db = new PDO('mysql:host=localhost;dbname=test_sistema_autenticacion', 'root', '');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->auth = new AuthManager($this->db);
        
        $this->db->exec("TRUNCATE TABLE usuarios");
        $this->db->exec("TRUNCATE TABLE sesiones");
        $this->db->exec("TRUNCATE TABLE logs_autenticacion");
        
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'PHPUnit Test';
    }
    
    protected function tearDown(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        $_SESSION = [];
    }
    
    public function testLoginSuccess() {
        // Crear usuario
        $password = 'TestPassword123!';
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, password, rol, activo) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', $hash, 'Docente', 1]);
        
        $result = $this->auth->login('testuser', $password);
        
        $this->assertTrue($result['success']);
        $this->assertArrayHasKey('user', $result);
        $this->assertEquals('testuser', $result['user']['username']);
    }
    
    public function testLoginInvalidCredentials() {
        $result = $this->auth->login('nonexistent', 'wrongpass');
        
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('inválidas', $result['message']);
    }
    
    public function testLoginAccountLocked() {
        $password = 'TestPassword123!';
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, password, rol, activo, bloqueado_hasta) VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE))");
        $stmt->execute(['testuser', 'test@example.com', $hash, 'Docente', 1]);
        
        $result = $this->auth->login('testuser', $password);
        
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('bloqueada', $result['message']);
    }
    
    public function testChangePasswordSuccess() {
        $oldPassword = 'OldPassword123!';
        $newPassword = 'NewPassword456@';
        $hash = password_hash($oldPassword, PASSWORD_ARGON2ID);
        
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, password, rol, activo) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', $hash, 'Asistente', 1]);
        $userId = $this->db->lastInsertId();
        
        $result = $this->auth->changePassword($userId, $oldPassword, $newPassword);
        
        $this->assertTrue($result['success']);
    }
    
    public function testChangePasswordWrongCurrent() {
        $oldPassword = 'OldPassword123!';
        $hash = password_hash($oldPassword, PASSWORD_ARGON2ID);
        
        $stmt = $this->db->prepare("INSERT INTO usuarios (username, email, password, rol, activo) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute(['testuser', 'test@example.com', $hash, 'Asistente', 1]);
        $userId = $this->db->lastInsertId();
        
        $result = $this->auth->changePassword($userId, 'WrongPassword', 'NewPassword456@');
        
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('incorrecta', $result['message']);
    }
}