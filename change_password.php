<?php
// change_password.php
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

// Verificar que necesita cambiar contraseña
if (!isset($_SESSION['must_change_password']) || !isset($_SESSION['temp_user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['temp_user_id'];
$error = '';
$errors = [];

// Procesar cambio
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change'])) {
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    
    if (empty($newPassword) || empty($confirmPassword)) {
        $error = 'Por favor complete todos los campos';
    } elseif ($newPassword !== $confirmPassword) {
        $error = 'Las contraseñas no coinciden';
    } else {
        $result = $auth->changePassword($userId, $currentPassword, $newPassword);
        
        if ($result['success']) {
            // Obtener usuario para hacer login
            $stmt = $db->prepare("SELECT username, rol FROM usuarios WHERE id = :id");
            $stmt->execute(['id' => $userId]);
            $usuario = $stmt->fetch();
            
            // Limpiar variables temporales
            unset($_SESSION['must_change_password']);
            unset($_SESSION['temp_user_id']);
            
            // Hacer login
            $session->login($userId, $usuario['username'], $usuario['rol']);
            
            header('Location: dashboard.php');
            exit;
        } else {
            $error = $result['message'];
            if (isset($result['errors'])) {
                $errors = $result['errors'];
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cambiar Contraseña</title>
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
            max-width: 480px;
            padding: 40px;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 12px;
            font-size: 24px;
        }
        
        .warning-banner {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 14px;
        }
        
        .warning-banner strong {
            display: block;
            margin-bottom: 4px;
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
        
        .error-list {
            margin-top: 8px;
            padding-left: 20px;
        }
        
        .error-list li {
            margin: 4px 0;
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
        
        .form-control {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        
        .form-control:focus {
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
        
        .requirements {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin-top: 20px;
            font-size: 13px;
        }
        
        .requirements h3 {
            color: #333;
            font-size: 14px;
            margin-bottom: 12px;
        }
        
        .requirements ul {
            margin: 0;
            padding-left: 20px;
        }
        
        .requirements li {
            margin: 6px 0;
            color: #6c757d;
        }
        
        .password-strength {
            margin-top: 8px;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            overflow: hidden;
        }
        
        .password-strength-bar {
            height: 100%;
            width: 0%;
            transition: all 0.3s;
        }
        
        .strength-weak { background: #dc3545; width: 33%; }
        .strength-medium { background: #ffc107; width: 66%; }
        .strength-strong { background: #28a745; width: 100%; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Cambio de Contraseña Requerido</h1>
        
        <div class="warning-banner">
            <strong>⚠️ Acción requerida</strong>
            Debe cambiar su contraseña antes de continuar. Su contraseña actual ha expirado o fue marcada para cambio.
        </div>
        
        <?php if ($error): ?>
            <div class="alert-error">
                <?= htmlspecialchars($error) ?>
                <?php if (!empty($errors)): ?>
                    <ul class="error-list">
                        <?php foreach ($errors as $err): ?>
                            <li><?= htmlspecialchars($err) ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="current_password">Contraseña Actual</label>
                <input 
                    type="password" 
                    id="current_password" 
                    name="current_password" 
                    class="form-control" 
                    required
                    autocomplete="current-password"
                >
            </div>
            
            <div class="form-group">
                <label for="new_password">Nueva Contraseña</label>
                <input 
                    type="password" 
                    id="new_password" 
                    name="new_password" 
                    class="form-control" 
                    required
                    autocomplete="new-password"
                >
                <div class="password-strength">
                    <div class="password-strength-bar" id="strengthBar"></div>
                </div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirmar Nueva Contraseña</label>
                <input 
                    type="password" 
                    id="confirm_password" 
                    name="confirm_password" 
                    class="form-control" 
                    required
                    autocomplete="new-password"
                >
            </div>
            
            <button type="submit" name="change" class="btn btn-primary">
                Cambiar Contraseña
            </button>
        </form>
        
        <div class="requirements">
            <h3>Requisitos de la contraseña:</h3>
            <ul>
                <li>Mínimo <?= PASSWORD_MIN_LENGTH ?> caracteres</li>
                <li>Al menos una letra mayúscula</li>
                <li>Al menos una letra minúscula</li>
                <li>Al menos un número</li>
                <li>Al menos un carácter especial (!@#$%^&*)</li>
                <li>No puede ser una contraseña común</li>
                <li>No puede reutilizar las últimas <?= PASSWORD_HISTORY_COUNT ?> contraseñas</li>
            </ul>
        </div>
    </div>
    
    <script>
        // Medidor de fortaleza de contraseña
        const passwordInput = document.getElementById('new_password');
        const strengthBar = document.getElementById('strengthBar');
        
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            
            if (password.length >= <?= PASSWORD_MIN_LENGTH ?>) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;
            
            strengthBar.className = 'password-strength-bar';
            if (strength <= 2) {
                strengthBar.classList.add('strength-weak');
            } else if (strength <= 4) {
                strengthBar.classList.add('strength-medium');
            } else {
                strengthBar.classList.add('strength-strong');
            }
        });
    </script>
</body>
</html>