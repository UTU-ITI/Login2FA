<?php
// admin/reports.php
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

// Configuración de fechas
$fechaInicio = $_GET['fecha_inicio'] ?? date('Y-m-d', strtotime('-30 days'));
$fechaFin = $_GET['fecha_fin'] ?? date('Y-m-d');

// Reporte 1: Intentos de login por día
$stmt = $db->prepare("
    SELECT DATE(created_at) as fecha,
           SUM(CASE WHEN tipo_evento = 'login_exitoso' THEN 1 ELSE 0 END) as exitosos,
           SUM(CASE WHEN tipo_evento = 'login_fallido' THEN 1 ELSE 0 END) as fallidos
    FROM logs_autenticacion
    WHERE tipo_evento IN ('login_exitoso', 'login_fallido')
    AND DATE(created_at) BETWEEN :inicio AND :fin
    GROUP BY DATE(created_at)
    ORDER BY fecha DESC
");
$stmt->execute(['inicio' => $fechaInicio, 'fin' => $fechaFin]);
$loginsPorDia = $stmt->fetchAll();

// Reporte 2: Top IPs con intentos fallidos
$stmt = $db->prepare("
    SELECT ip_address, COUNT(*) as intentos,
           MAX(created_at) as ultimo_intento
    FROM logs_autenticacion
    WHERE tipo_evento = 'login_fallido'
    AND DATE(created_at) BETWEEN :inicio AND :fin
    GROUP BY ip_address
    ORDER BY intentos DESC
    LIMIT 10
");
$stmt->execute(['inicio' => $fechaInicio, 'fin' => $fechaFin]);
$topIPsFallidos = $stmt->fetchAll();

// Reporte 3: Usuarios con más intentos fallidos
$stmt = $db->prepare("
    SELECT u.username, u.email, u.intentos_fallidos, u.bloqueado_hasta,
           COUNT(l.id) as total_fallos
    FROM usuarios u
    LEFT JOIN logs_autenticacion l ON u.id = l.usuario_id 
        AND l.tipo_evento = 'login_fallido'
        AND DATE(l.created_at) BETWEEN :inicio AND :fin
    GROUP BY u.id
    HAVING total_fallos > 0
    ORDER BY total_fallos DESC
    LIMIT 10
");
$stmt->execute(['inicio' => $fechaInicio, 'fin' => $fechaFin]);
$usuariosFallidos = $stmt->fetchAll();

// Reporte 4: Contraseñas próximas a expirar
$stmt = $db->query("
    SELECT username, email, rol, ultima_modificacion_password,
           DATEDIFF(DATE_ADD(ultima_modificacion_password, INTERVAL " . PASSWORD_EXPIRY_DAYS . " DAY), NOW()) as dias_restantes
    FROM usuarios
    WHERE rol IN ('Asistente', 'Administrativo')
    AND ultima_modificacion_password IS NOT NULL
    AND DATEDIFF(DATE_ADD(ultima_modificacion_password, INTERVAL " . PASSWORD_EXPIRY_DAYS . " DAY), NOW()) <= 14
    AND DATEDIFF(DATE_ADD(ultima_modificacion_password, INTERVAL " . PASSWORD_EXPIRY_DAYS . " DAY), NOW()) > 0
    ORDER BY dias_restantes ASC
");
$passwordsPorExpirar = $stmt->fetchAll();

// Reporte 5: Actividad por rol
$stmt = $db->prepare("
    SELECT u.rol,
           COUNT(DISTINCT l.usuario_id) as usuarios_activos,
           COUNT(l.id) as total_eventos
    FROM usuarios u
    LEFT JOIN logs_autenticacion l ON u.id = l.usuario_id
        AND DATE(l.created_at) BETWEEN :inicio AND :fin
    GROUP BY u.rol
    ORDER BY total_eventos DESC
");
$stmt->execute(['inicio' => $fechaInicio, 'fin' => $fechaFin]);
$actividadPorRol = $stmt->fetchAll();

// Reporte 6: Sesiones activas por hora del día
$stmt = $db->query("
    SELECT HOUR(ultima_actividad) as hora, COUNT(*) as sesiones
    FROM sesiones
    WHERE ultima_actividad >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    GROUP BY HOUR(ultima_actividad)
    ORDER BY hora
");
$sesionesPorHora = $stmt->fetchAll();

// Reporte 7: Eventos 2FA
$stmt = $db->prepare("
    SELECT DATE(created_at) as fecha,
           SUM(CASE WHEN tipo_evento = '2fa_exitoso' THEN 1 ELSE 0 END) as exitosos,
           SUM(CASE WHEN tipo_evento = '2fa_fallido' THEN 1 ELSE 0 END) as fallidos
    FROM logs_autenticacion
    WHERE tipo_evento IN ('2fa_exitoso', '2fa_fallido')
    AND DATE(created_at) BETWEEN :inicio AND :fin
    GROUP BY DATE(created_at)
    ORDER BY fecha DESC
");
$stmt->execute(['inicio' => $fechaInicio, 'fin' => $fechaFin]);
$eventos2FA = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reportes de Seguridad</title>
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
        
        .filter-section {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 24px;
        }
        
        .filter-form {
            display: flex;
            gap: 16px;
            align-items: end;
        }
        
        .form-group {
            flex: 1;
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
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .btn {
            padding: 10px 24px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .reports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 24px;
        }
        
        .report-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .report-card h2 {
            font-size: 18px;
            color: #333;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .report-card.full-width {
            grid-column: 1 / -1;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #e0e0e0;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
        }
        
        tr:last-child td {
            border-bottom: none;
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
        
        .chart-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }
        
        .chart-bar-label {
            min-width: 100px;
            font-size: 13px;
            color: #6c757d;
        }
        
        .chart-bar-container {
            flex: 1;
            height: 24px;
            background: #f0f0f0;
            border-radius: 12px;
            overflow: hidden;
        }
        
        .chart-bar-fill {
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s;
        }
        
        .chart-bar-value {
            min-width: 40px;
            text-align: right;
            font-weight: 600;
            color: #333;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <h1>📊 Reportes de Seguridad</h1>
            <div class="navbar-links">
                <a href="index.php">Panel Admin</a>
                <a href="../dashboard.php">Dashboard</a>
                <a href="../logout.php">Cerrar Sesión</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="filter-section">
            <form method="GET" class="filter-form">
                <div class="form-group">
                    <label>Fecha Inicio</label>
                    <input type="date" name="fecha_inicio" class="form-control" value="<?= $fechaInicio ?>">
                </div>
                <div class="form-group">
                    <label>Fecha Fin</label>
                    <input type="date" name="fecha_fin" class="form-control" value="<?= $fechaFin ?>">
                </div>
                <button type="submit" class="btn btn-primary">Filtrar</button>
            </form>
        </div>
        
        <div class="reports-grid">
            <!-- Reporte 1: Logins por día -->
            <div class="report-card">
                <h2>📈 Intentos de Login por Día</h2>
                <?php if (empty($loginsPorDia)): ?>
                    <div class="no-data">No hay datos para el período seleccionado</div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Fecha</th>
                                <th>Exitosos</th>
                                <th>Fallidos</th>
                                <th>Total</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($loginsPorDia as $dia): ?>
                                <tr>
                                    <td><?= date('d/m/Y', strtotime($dia['fecha'])) ?></td>
                                    <td><span class="badge badge-success"><?= $dia['exitosos'] ?></span></td>
                                    <td><span class="badge badge-danger"><?= $dia['fallidos'] ?></span></td>
                                    <td><?= $dia['exitosos'] + $dia['fallidos'] ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            
            <!-- Reporte 2: Top IPs fallidos -->
            <div class="report-card">
                <h2>🚨 Top IPs con Intentos Fallidos</h2>
                <?php if (empty($topIPsFallidos)): ?>
                    <div class="no-data">No hay intentos fallidos</div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Intentos</th>
                                <th>Último Intento</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($topIPsFallidos as $ip): ?>
                                <tr>
                                    <td><?= htmlspecialchars($ip['ip_address']) ?></td>
                                    <td><span class="badge badge-danger"><?= $ip['intentos'] ?></span></td>
                                    <td><?= date('d/m/Y H:i', strtotime($ip['ultimo_intento'])) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            
            <!-- Reporte 3: Usuarios con fallos -->
            <div class="report-card">
                <h2>👤 Usuarios con Intentos Fallidos</h2>
                <?php if (empty($usuariosFallidos)): ?>
                    <div class="no-data">No hay usuarios con fallos</div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Usuario</th>
                                <th>Email</th>
                                <th>Total Fallos</th>
                                <th>Estado</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($usuariosFallidos as $usuario): ?>
                                <tr>
                                    <td><?= htmlspecialchars($usuario['username']) ?></td>
                                    <td><?= htmlspecialchars($usuario['email']) ?></td>
                                    <td><span class="badge badge-danger"><?= $usuario['total_fallos'] ?></span></td>
                                    <td>
                                        <?php if ($usuario['bloqueado_hasta'] && strtotime($usuario['bloqueado_hasta']) > time()): ?>
                                            <span class="badge badge-danger">Bloqueado</span>
                                        <?php else: ?>
                                            <span class="badge badge-success">OK</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            
            <!-- Reporte 4: Contraseñas por expirar -->
            <div class="report-card">
                <h2>⏰ Contraseñas Próximas a Expirar</h2>
                <?php if (empty($passwordsPorExpirar)): ?>
                    <div class="no-data">No hay contraseñas próximas a expirar</div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Usuario</th>
                                <th>Rol</th>
                                <th>Días Restantes</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($passwordsPorExpirar as $user): ?>
                                <tr>
                                    <td><?= htmlspecialchars($user['username']) ?></td>
                                    <td><?= htmlspecialchars($user['rol']) ?></td>
                                    <td>
                                        <span class="badge <?= $user['dias_restantes'] <= 7 ? 'badge-danger' : 'badge-warning' ?>">
                                            <?= $user['dias_restantes'] ?> días
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            
            <!-- Reporte 5: Actividad por rol -->
            <div class="report-card full-width">
                <h2>📊 Actividad por Rol</h2>
                <?php if (empty($actividadPorRol)): ?>
                    <div class="no-data">No hay actividad registrada</div>
                <?php else: ?>
                    <?php 
                    $maxEventos = max(array_column($actividadPorRol, 'total_eventos'));
                    ?>
                    <?php foreach ($actividadPorRol as $rol): ?>
                        <div class="chart-bar">
                            <div class="chart-bar-label"><?= htmlspecialchars($rol['rol']) ?></div>
                            <div class="chart-bar-container">
                                <div class="chart-bar-fill" style="width: <?= $maxEventos > 0 ? ($rol['total_eventos'] / $maxEventos * 100) : 0 ?>%"></div>
                            </div>
                            <div class="chart-bar-value"><?= $rol['total_eventos'] ?></div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <!-- Reporte 6: Sesiones por hora -->
            <div class="report-card full-width">
                <h2>🕐 Sesiones Activas por Hora (Últimas 24h)</h2>
                <?php if (empty($sesionesPorHora)): ?>
                    <div class="no-data">No hay sesiones activas</div>
                <?php else: ?>
                    <?php $maxSesiones = max(array_column($sesionesPorHora, 'sesiones')); ?>
                    <?php foreach ($sesionesPorHora as $hora): ?>
                        <div class="chart-bar">
                            <div class="chart-bar-label"><?= sprintf('%02d:00', $hora['hora']) ?></div>
                            <div class="chart-bar-container">
                                <div class="chart-bar-fill" style="width: <?= $maxSesiones > 0 ? ($hora['sesiones'] / $maxSesiones * 100) : 0 ?>%"></div>
                            </div>
                            <div class="chart-bar-value"><?= $hora['sesiones'] ?></div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <!-- Reporte 7: Eventos 2FA -->
            <div class="report-card">
                <h2>🔐 Eventos 2FA</h2>
                <?php if (empty($eventos2FA)): ?>
                    <div class="no-data">No hay eventos 2FA en el período</div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Fecha</th>
                                <th>Exitosos</th>
                                <th>Fallidos</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($eventos2FA as $evento): ?>
                                <tr>
                                    <td><?= date('d/m/Y', strtotime($evento['fecha'])) ?></td>
                                    <td><span class="badge badge-success"><?= $evento['exitosos'] ?></span></td>
                                    <td><span class="badge badge-danger"><?= $evento['fallidos'] ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>