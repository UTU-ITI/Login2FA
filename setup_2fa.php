<?php
// setup_2fa.php
require_once 'config/database.php';
require_once 'config/constants.php';
require_once 'classes/SessionManager.php';
require_once 'classes/AuthManager.php';
require_once 'classes/PasswordPolicy.php';
require_once 'classes/TwoFactorAuth.php';

$db = Database::getConnection();
$auth = new AuthManager($db);
$session = $auth->getSessionManager();
$session->start();

// Verificar autenticación
if (!$auth->isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$userId = $session->getUserId();
$username = $session->getUsername();
$rol = $session->getRol();

// Verificar que el rol requiere 2FA
if (!in_array($rol, ROLES_2FA)) {
    header('Location: dashboard.php');
    exit;
}

$twoFA = $auth->getTwoFactorAuth();
$error = '';
$step = 1;

// Generar secret si no existe en sesión
if (!isset($_SESSION['setup_2fa_secret'])) {
    $_SESSION['setup_2fa_secret'] = $twoFA->generateSecret();
}

$secret = $_SESSION['setup_2fa_secret'];
$qrCodeUrl = $twoFA->getQRCodeUrl($secret, $username);

// Procesar verificación
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify'])) {
    $code = trim($_POST['code'] ?? '');
    
    if (empty($code)) {
        $error = 'Por favor ingrese el código';
    } elseif (!preg_match('/^\d{6}$/', $code)) {
        $error = 'El código debe tener 6 dígitos';
    } else {
        if ($twoFA->verifyCode($secret, $code)) {
            // Habilitar 2FA
            $stmt = $db->prepare("UPDATE usuarios SET secret_2fa = :secret WHERE id = :id");
            $stmt->execute(['secret' => $secret, 'id' => $userId]);
            
            // Generar códigos de backup
            $backupCodes = $twoFA->generateBackupCodes();
            $_SESSION['backup_codes'] = $backupCodes;
            
            // Limpiar secret de sesión
            unset($_SESSION['setup_2fa_secret']);
            
            $step = 3; // Mostrar códigos de backup
        } else {
            $error = 'Código inválido. Intente nuevamente.';
        }
    }
}

if (isset($_POST['finish'])) {
    unset($_SESSION['backup_codes']);
    header('Location: dashboard.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurar 2FA</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 500px;
            padding: 40px;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 8px;
            font-size: 24px;
        }
        
        .subtitle {
            text-align: center;
            color: #6c757d;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .steps {
            display: flex;
            justify-content: center;
            margin-bottom: 30px;
            gap: 8px;
        }
        
        .step-indicator {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: #e0e0e0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
            color: #6c757d;
        }
        
        .step-indicator.active {
            background: #667eea;
            color: white;
        }
        
        .step-indicator.completed {
            background: #28a745;
            color: white;
        }
        
        .qr-container {
            text-align: center;
            margin: 24px 0;
        }
        
        .qr-code {
            display: inline-block;
            padding: 16px;
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
        }
        
        .secret-box {
            background: #f8f9fa;
            padding: 16px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
            word-break: break-all;
        }
        
        .secret-box code {
            font-size: 16px;
            font-weight: 600;
            color: #333;
            letter-spacing: 2px;
        }
        
        .alert-error {
            background-color: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        
        .code-input {
            width: 100%;
            padding: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 24px;
            text-align: center;
            letter-spacing: 8px;
            font-weight: 600;
        }
        
        .code-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }
        
        .instructions {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin: 20px 0;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .instructions ol {
            padding-left: 20px;
        }
        
        .instructions li {
            margin: 8px 0;
        }
        
        .backup-codes {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .backup-codes-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-top: 16px;
        }
        
        .backup-code {
            background: white;
            padding: 12px;
            border-radius: 6px;
            text-align: center;
            font-family: monospace;
            font-size: 14px;
            font-weight: 600;
            border: 1px solid #e0e0e0;
        }
        
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 16px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 14px;
        }
        
        .cancel-link {
            text-align: center;
            margin-top: 16px;
        }
        
        .cancel-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($step < 3): ?>
            <h1>🔐 Configurar 2FA</h1>
            <p class="subtitle">Autenticación de Dos Factores</p>
            
            <div class="steps">
                <div class="step-indicator completed">1</div>
                <div class="step-indicator <?= $step >= 2 ? 'active' : '' ?>">2</div>
                <div class="step-indicator">3</div>
            </div>
            
            <div class="instructions">
                <strong>Instrucciones:</strong>
                <ol>
                    <li>Descargue una aplicación de autenticación (Google Authenticator, Microsoft Authenticator, Authy, etc.)</li>
                    <li>Escanee el código QR con la aplicación</li>
                    <li>Ingrese el código de 6 dígitos que aparece en la aplicación</li>
                </ol>
            </div>
            
            <div class="qr-container">
                <div class="qr-code">
                    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=<?= urlencode($qrCodeUrl) ?>" 
                         alt="QR Code" 
                         width="200" 
                         height="200">
                </div>
            </div>
            
            <div class="secret-box">
                <div style="font-size: 13px; color: #6c757d; margin-bottom: 8px;">
                    O ingrese manualmente esta clave:
                </div>
                <code><?= htmlspecialchars($secret) ?></code>
            </div>
            
            <?php if ($error): ?>
                <div class="alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="code">Código de Verificación</label>
                    <input 
                        type="text" 
                        id="code" 
                        name="code" 
                        class="code-input" 
                        maxlength="6"
                        pattern="\d{6}"
                        inputmode="numeric"
                        autocomplete="one-time-code"
                        required 
                        autofocus
                    >
                </div>
                
                <button type="submit" name="verify" class="btn btn-primary">
                    Verificar y Activar 2FA
                </button>
            </form>
            
            <div class="cancel-link">
                <a href="dashboard.php">Cancelar</a>
            </div>
            
        <?php else: ?>
            <h1>✅ 2FA Habilitado</h1>
            <p class="subtitle">Códigos de Respaldo</p>
            
            <div class="steps">
                <div class="step-indicator completed">1</div>
                <div class="step-indicator completed">2</div>
                <div class="step-indicator active">3</div>
            </div>
            
            <div class="warning-box">
                <strong>⚠️ Importante:</strong> Guarde estos códigos en un lugar seguro. 
                Puede usarlos para acceder a su cuenta si pierde acceso a su aplicación de autenticación.
            </div>
            
            <div class="backup-codes">
                <strong>Códigos de Respaldo:</strong>
                <div class="backup-codes-grid">
                    <?php foreach ($_SESSION['backup_codes'] as $code): ?>
                        <div class="backup-code"><?= htmlspecialchars($code) ?></div>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <div class="instructions">
                <strong>Recomendaciones:</strong>
                <ul>
                    <li>Imprima estos códigos y guárdelos en un lugar seguro</li>
                    <li>Cada código solo puede usarse una vez</li>
                    <li>No comparta estos códigos con nadie</li>
                </ul>
            </div>
            
            <form method="POST" action="">
                <button type="submit" name="finish" class="btn btn-primary">
                    He guardado los códigos
                </button>
            </form>
        <?php endif; ?>
    </div>
    
    <script>
        // Auto-submit cuando se ingresan 6 dígitos
        const codeInput = document.getElementById('code');
        if (codeInput) {
            codeInput.addEventListener('input', function(e) {
                this.value = this.value.replace(/\D/g, '');
            });
        }
    </script>
</body>
</html>