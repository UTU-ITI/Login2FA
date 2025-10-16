<?php
// profile.php
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

// Obtener información del usuario
$stmt = $db->prepare("
    SELECT username, email, rol, github_id, ultima_modificacion_password, 
           created_at, secret_2fa
    FROM usuarios 
    WHERE id = :id
");
$stmt->execute(['id' => $userId]);
$usuario = $stmt->fetch();

// No permitir cambio de password para usuarios GitHub
if ($usuario['github_id']) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';
$errors = [];

// Procesar cambio de contraseña
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    
    if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
        $error = 'Por favor complete todos los campos';
    } elseif ($newPassword !== $confirmPassword) {
        $error = 'Las contraseñas nuevas no coinciden';
    } else {
        $result = $auth->changePassword($userId, $currentPassword, $newPassword);
        
        if ($result['success']) {
            $success = $result['message'];
            // Actualizar información
            $stmt->execute(['id' => $userId]);
            $usuario = $stmt->fetch();
        } else {
            $error = $result['message'];
            if (isset($result['errors'])) {
                $errors = $result['errors'];
            }
        }
    }
}

// Calcular días desde último cambio
$daysSinceChange = null;
if ($usuario['ultima_modificacion_password']) {
    $daysSinceChange = floor((time() - strtotime($usuario['ultima_modificacion_password'])) / (60 * 60 * 24));
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mi Perfil - <?= htmlspecialchars($username) ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 16px 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .navbar-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .navbar h1 {
            font-size: 20px;
        }
        
        .navbar-links {
            display: flex;
            gap: 16px;
        }
        
        .navbar-links a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            transition: background 0.3s;
        }
        
        .navbar-links a:hover {
            background: rgba(255,255,255,0.2);
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 24px;
        }
        
        .alert {
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }
        
        .alert-success {
            background: #efe;
            border: 1px solid #cfc;
            color: #3c3;
        }
        
        .alert-warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
        }
        
        .error-list {
            margin-top: 8px;
            padding-left: 20px;
        }
        
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .card h2 {
            font-size: 18px;
            color: #333;
            margin-bottom: 16px;
        }
        
        .info-item {
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-size: 13px;
            color: #6c757d;
            margin-bottom: 4px;
        }
        
        .info-value {
            font-size: 15px;
            color: #333;
            font-weight: 500;
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
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            width: 100%;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        
        .requirements {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
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
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <h1>👤 Mi Perfil</h1>
            <div class="navbar-links">
                <a href="dashboard.php">Dashboard</a>
                <?php if ($rol === 'SysAdmin'): ?>
                    <a href="admin/index.php">Panel Admin</a>
                <?php endif; ?>
                <a href="logout.php">Cerrar Sesión</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
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
        
        <?php if (in_array($rol, ROLES_CON_POLITICAS) && $daysSinceChange !== null): ?>
            <?php 
            $daysRemaining = PASSWORD_EXPIRY_DAYS - $daysSinceChange;
            if ($daysRemaining <= 14 && $daysRemaining > 0): 
            ?>
                <div class="alert alert-warning">
                    ⚠️ <strong>Advertencia:</strong> Su contraseña expirará en <?= $daysRemaining ?> día(s). 
                    Se recomienda cambiarla pronto.
                </div>
            <?php elseif ($daysRemaining <= 0): ?>
                <div class="alert alert-error">
                    🔒 <strong>Contraseña Expirada:</strong> Su contraseña ha expirado. 
                    Debe cambiarla inmediatamente.
                </div>
            <?php endif; ?>
        <?php endif; ?>
        
        <div class="grid">
            <div class="card">
                <h2>Información Personal</h2>
                <div class="info-item">
                    <div class="info-label">Usuario</div>
                    <div class="info-value"><?= htmlspecialchars($usuario['username']) ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Email</div>
                    <div class="info-value"><?= htmlspecialchars($usuario['email']) ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Rol</div>
                    <div class="info-value"><?= htmlspecialchars($usuario['rol']) ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Miembro desde</div>
                    <div class="info-value"><?= date('d/m/Y', strtotime($usuario['created_at'])) ?></div>
                </div>
            </div>
            
            <div class="card">
                <h2>Seguridad</h2>
                <div class="info-item">
                    <div class="info-label">Último cambio de contraseña</div>
                    <div class="info-value">
                        <?php if ($usuario['ultima_modificacion_password']): ?>
                            <?= date('d/m/Y', strtotime($usuario['ultima_modificacion_password'])) ?>
                            <?php if ($daysSinceChange !== null): ?>
                                <span class="badge <?= $daysSinceChange > 60 ? 'badge-warning' : 'badge-success' ?>">
                                    Hace <?= $daysSinceChange ?> días
                                </span>
                            <?php endif; ?>
                        <?php else: ?>
                            Nunca
                            <span class="badge badge-danger">Cambiar pronto</span>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Autenticación 2FA</div>
                    <div class="info-value">
                        <?php if ($usuario['secret_2fa']): ?>
                            <span class="badge badge-success">✓ Habilitado</span>
                        <?php else: ?>
                            <span class="badge badge-danger">✗ Deshabilitado</span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card" style="margin-top: 24px;">
            <h2>Cambiar Contraseña</h2>
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
                
                <button type="submit" name="change_password" class="btn btn-primary">
                    Cambiar Contraseña
                </button>
            </form>
            
            <?php if (in_array($rol, ROLES_CON_POLITICAS)): ?>
                <div class="requirements">
                    <h3>Requisitos de la contraseña:</h3>
                    <ul>
                        <li>Mínimo <?= PASSWORD_MIN_LENGTH ?> caracteres</li>
                        <li>Al menos una letra mayúscula</li>
                        <li>Al menos una letra minúscula</li>
                        <li>Al menos un número</li>
                        <li>Al menos un carácter especial (!@#$%^&*)</li>
                        <li>No puede reutilizar las últimas <?= PASSWORD_HISTORY_COUNT ?> contraseñas</li>
                        <li>Debe cambiarla cada <?= PASSWORD_EXPIRY_DAYS ?> días</li>
                    </ul>
                </div>
            <?php else: ?>
                <div class="requirements">
                    <h3>Recomendaciones:</h3>
                    <ul>
                        <li>Use una contraseña segura y única</li>
                        <li>Combine letras, números y símbolos</li>
                        <li>Evite información personal</li>
                        <li>Cambie su contraseña regularmente</li>
                    </ul>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <script>
        const passwordInput = document.getElementById('new_password');
        const strengthBar = document.getElementById('strengthBar');
        
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            
            if (password.length >= <?= in_array($rol, ROLES_CON_POLITICAS) ? PASSWORD_MIN_LENGTH : 8 ?>) strength++;
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