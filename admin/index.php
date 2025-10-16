<?php
// admin/index.php
require_once '../config/database.php';
require_once '../config/constants.php';
require_once '../classes/SessionManager.php';
require_once '../classes/AuthManager.php';
require_once '../classes/PasswordPolicy.php';
require_once '../classes/TwoFactorAuth.php';

$db = Database::getConnection();
$auth = new AuthManager($db);
$session = $auth->getSessionManager();
$session->start();

// Verificar que es SysAdmin
if (!$auth->isAuthenticated() || $session->getRol() !== 'SysAdmin') {
    header('Location: ../login.php');
    exit;
}

$passwordPolicy = new PasswordPolicy($db);
$message = '';
$error = '';

// Procesar acciones
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'create':
                $username = trim($_POST['username']);
                $email = trim($_POST['email']);
                $rol = $_POST['rol'];
                $password = $passwordPolicy->generateSecurePassword(16);
                
                try {
                    $hash = password_hash($password, PASSWORD_ARGON2ID, [
                        'memory_cost' => 65536,
                        'time_cost' => 4,
                        'threads' => 3
                    ]);
                    
                    $stmt = $db->prepare("
                        INSERT INTO usuarios (username, email, password, rol, debe_cambiar_password, activo)
                        VALUES (:username, :email, :password, :rol, TRUE, TRUE)
                    ");
                    
                    $stmt->execute([
                        'username' => $username,
                        'email' => $email,
                        'password' => $rol === 'Estudiante' ? null : $hash,
                        'rol' => $rol
                    ]);
                    
                    $message = "Usuario creado exitosamente. Password temporal: <strong>$password</strong>";
                } catch (PDOException $e) {
                    $error = "Error al crear usuario: " . $e->getMessage();
                }
                break;
                
            case 'update':
                $userId = $_POST['user_id'];
                $username = trim($_POST['username']);
                $email = trim($_POST['email']);
                $rol = $_POST['rol'];
                $activo = isset($_POST['activo']) ? 1 : 0;
                
                try {
                    $stmt = $db->prepare("
                        UPDATE usuarios 
                        SET username = :username, email = :email, rol = :rol, activo = :activo
                        WHERE id = :id
                    ");
                    
                    $stmt->execute([
                        'username' => $username,
                        'email' => $email,
                        'rol' => $rol,
                        'activo' => $activo,
                        'id' => $userId
                    ]);
                    
                    $message = "Usuario actualizado exitosamente";
                } catch (PDOException $e) {
                    $error = "Error al actualizar usuario: " . $e->getMessage();
                }
                break;
                
            case 'delete':
                $userId = $_POST['user_id'];
                
                try {
                    $stmt = $db->prepare("DELETE FROM usuarios WHERE id = :id");
                    $stmt->execute(['id' => $userId]);
                    $message = "Usuario eliminado exitosamente";
                } catch (PDOException $e) {
                    $error = "Error al eliminar usuario: " . $e->getMessage();
                }
                break;
                
            case 'reset_password':
                $userId = $_POST['user_id'];
                $newPassword = $passwordPolicy->generateSecurePassword(16);
                $hash = password_hash($newPassword, PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536,
                    'time_cost' => 4,
                    'threads' => 3
                ]);
                
                try {
                    $stmt = $db->prepare("
                        UPDATE usuarios 
                        SET password = :password, 
                            debe_cambiar_password = TRUE,
                            ultima_modificacion_password = NOW()
                        WHERE id = :id
                    ");
                    
                    $stmt->execute([
                        'password' => $hash,
                        'id' => $userId
                    ]);
                    
                    $message = "Password reseteada exitosamente. Nueva password: <strong>$newPassword</strong>";
                } catch (PDOException $e) {
                    $error = "Error al resetear password: " . $e->getMessage();
                }
                break;
                
            case 'unlock':
                $userId = $_POST['user_id'];
                
                try {
                    $stmt = $db->prepare("
                        UPDATE usuarios 
                        SET intentos_fallidos = 0, bloqueado_hasta = NULL
                        WHERE id = :id
                    ");
                    
                    $stmt->execute(['id' => $userId]);
                    $message = "Cuenta desbloqueada exitosamente";
                } catch (PDOException $e) {
                    $error = "Error al desbloquear cuenta: " . $e->getMessage();
                }
                break;
        }
    }
}

// Obtener lista de usuarios
$search = $_GET['search'] ?? '';
$rolFilter = $_GET['rol'] ?? '';

$query = "SELECT * FROM usuarios WHERE 1=1";
$params = [];

if ($search) {
    $query .= " AND (username LIKE :search OR email LIKE :search)";
    $params['search'] = "%$search%";
}

if ($rolFilter) {
    $query .= " AND rol = :rol";
    $params['rol'] = $rolFilter;
}

$query .= " ORDER BY created_at DESC";

$stmt = $db->prepare($query);
$stmt->execute($params);
$usuarios = $stmt->fetchAll();

// Obtener estadísticas
$stats = [
    'total' => $db->query("SELECT COUNT(*) FROM usuarios")->fetchColumn(),
    'activos' => $db->query("SELECT COUNT(*) FROM usuarios WHERE activo = TRUE")->fetchColumn(),
    'bloqueados' => $db->query("SELECT COUNT(*) FROM usuarios WHERE bloqueado_hasta > NOW()")->fetchColumn(),
    'con_2fa' => $db->query("SELECT COUNT(*) FROM usuarios WHERE secret_2fa IS NOT NULL")->fetchColumn(),
];
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Administración</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 16px 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .navbar-content {
            max-width: 1400px;
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
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 8px;
        }
        
        .stat-label {
            color: #6c757d;
            font-size: 14px;
        }
        
        .alert {
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .alert-error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            gap: 16px;
            flex-wrap: wrap;
        }
        
        .search-form {
            display: flex;
            gap: 8px;
            flex: 1;
            max-width: 600px;
        }
        
        .search-form input, .search-form select {
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .search-form input {
            flex: 1;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-warning {
            background: #ffc107;
            color: #333;
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }
        
        .table-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 16px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #e0e0e0;
        }
        
        td {
            padding: 16px;
            border-bottom: 1px solid #f0f0f0;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
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
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-info {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background: white;
            margin: 5% auto;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        
        .modal-header {
            margin-bottom: 20px;
        }
        
        .modal-header h2 {
            font-size: 24px;
            color: #333;
        }
        
        .close {
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #999;
        }
        
        .close:hover {
            color: #333;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 8px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <h1>⚙️ Panel de Administración</h1>
            <div class="navbar-links">
                <a href="../dashboard.php">Dashboard</a>
                <a href="reports.php">Reportes</a>
                <a href="../logout.php">Cerrar Sesión</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <?php if ($message): ?>
            <div class="alert alert-success"><?= $message ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value"><?= $stats['total'] ?></div>
                <div class="stat-label">Total Usuarios</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= $stats['activos'] ?></div>
                <div class="stat-label">Usuarios Activos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= $stats['bloqueados'] ?></div>
                <div class="stat-label">Cuentas Bloqueadas</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= $stats['con_2fa'] ?></div>
                <div class="stat-label">Con 2FA</div>
            </div>
        </div>
        
        <div class="actions">
            <form method="GET" class="search-form">
                <input type="text" name="search" placeholder="Buscar por usuario o email..." value="<?= htmlspecialchars($search) ?>">
                <select name="rol">
                    <option value="">Todos los roles</option>
                    <option value="Estudiante" <?= $rolFilter === 'Estudiante' ? 'selected' : '' ?>>Estudiante</option>
                    <option value="Docente" <?= $rolFilter === 'Docente' ? 'selected' : '' ?>>Docente</option>
                    <option value="Asistente" <?= $rolFilter === 'Asistente' ? 'selected' : '' ?>>Asistente</option>
                    <option value="Administrativo" <?= $rolFilter === 'Administrativo' ? 'selected' : '' ?>>Administrativo</option>
                    <option value="SysAdmin" <?= $rolFilter === 'SysAdmin' ? 'selected' : '' ?>>SysAdmin</option>
                </select>
                <button type="submit" class="btn btn-primary">Buscar</button>
            </form>
            <button onclick="openModal('createModal')" class="btn btn-success">+ Nuevo Usuario</button>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Email</th>
                        <th>Rol</th>
                        <th>Estado</th>
                        <th>2FA</th>
                        <th>Método Auth</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($usuarios as $usuario): ?>
                        <tr>
                            <td><?= $usuario['id'] ?></td>
                            <td><?= htmlspecialchars($usuario['username']) ?></td>
                            <td><?= htmlspecialchars($usuario['email']) ?></td>
                            <td><span class="badge badge-info"><?= htmlspecialchars($usuario['rol']) ?></span></td>
                            <td>
                                <?php if ($usuario['bloqueado_hasta'] && strtotime($usuario['bloqueado_hasta']) > time()): ?>
                                    <span class="badge badge-danger">Bloqueado</span>
                                <?php elseif ($usuario['activo']): ?>
                                    <span class="badge badge-success">Activo</span>
                                <?php else: ?>
                                    <span class="badge badge-danger">Inactivo</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($usuario['secret_2fa']): ?>
                                    <span class="badge badge-success">✓</span>
                                <?php else: ?>
                                    <span class="badge badge-danger">✗</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($usuario['github_id']): ?>
                                    <span class="badge badge-info">GitHub</span>
                                <?php else: ?>
                                    <span class="badge badge-warning">Password</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <button onclick="editUser(<?= htmlspecialchars(json_encode($usuario)) ?>)" class="btn btn-primary btn-sm">Editar</button>
                                <?php if (!$usuario['github_id']): ?>
                                    <form method="POST" style="display:inline;" onsubmit="return confirm('¿Resetear password?')">
                                        <input type="hidden" name="action" value="reset_password">
                                        <input type="hidden" name="user_id" value="<?= $usuario['id'] ?>">
                                        <button type="submit" class="btn btn-warning btn-sm">Reset Pass</button>
                                    </form>
                                <?php endif; ?>
                                <?php if ($usuario['bloqueado_hasta'] && strtotime($usuario['bloqueado_hasta']) > time()): ?>
                                    <form method="POST" style="display:inline;">
                                        <input type="hidden" name="action" value="unlock">
                                        <input type="hidden" name="user_id" value="<?= $usuario['id'] ?>">
                                        <button type="submit" class="btn btn-success btn-sm">Desbloquear</button>
                                    </form>
                                <?php endif; ?>
                                <?php if ($usuario['id'] != $session->getUserId()): ?>
                                    <form method="POST" style="display:inline;" onsubmit="return confirm('¿Eliminar usuario?')">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="user_id" value="<?= $usuario['id'] ?>">
                                        <button type="submit" class="btn btn-danger btn-sm">Eliminar</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- Modal Crear Usuario -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close" onclick="closeModal('createModal')">&times;</span>
                <h2>Nuevo Usuario</h2>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="create">
                <div class="form-group">
                    <label>Usuario</label>
                    <input type="text" name="username" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Rol</label>
                    <select name="rol" class="form-control" required>
                        <option value="Estudiante">Estudiante</option>
                        <option value="Docente">Docente</option>
                        <option value="Asistente">Asistente</option>
                        <option value="Administrativo">Administrativo</option>
                        <option value="SysAdmin">SysAdmin</option>
                    </select>
                </div>
                <p style="color: #6c757d; font-size: 13px; margin-bottom: 20px;">
                    Se generará una contraseña temporal automáticamente (excepto para Estudiantes).
                </p>
                <button type="submit" class="btn btn-success" style="width: 100%;">Crear Usuario</button>
            </form>
        </div>
    </div>
    
    <!-- Modal Editar Usuario -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close" onclick="closeModal('editModal')">&times;</span>
                <h2>Editar Usuario</h2>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="user_id" id="edit_user_id">
                <div class="form-group">
                    <label>Usuario</label>
                    <input type="text" name="username" id="edit_username" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" id="edit_email" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Rol</label>
                    <select name="rol" id="edit_rol" class="form-control" required>
                        <option value="Estudiante">Estudiante</option>
                        <option value="Docente">Docente</option>
                        <option value="Asistente">Asistente</option>
                        <option value="Administrativo">Administrativo</option>
                        <option value="SysAdmin">SysAdmin</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="activo" id="edit_activo" value="1">
                        Usuario Activo
                    </label>
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">Actualizar Usuario</button>
            </form>
        </div>
    </div>
    
    <script>
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        function editUser(user) {
            document.getElementById('edit_user_id').value = user.id;
            document.getElementById('edit_username').value = user.username;
            document.getElementById('edit_email').value = user.email;
            document.getElementById('edit_rol').value = user.rol;
            document.getElementById('edit_activo').checked = user.activo == 1;
            openModal('editModal');
        }
        
        window.onclick = function(event) {
            if (event.target.className === 'modal') {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>