
<?php
require_once __DIR__ . '/../includes/auth.php';

$user = current_user();

if (!$user) {
    header('Location: ../index.php');
    exit;
}

if (!in_array(
    $user['role_name'],
    ['administrator', 'hr_officer'],
    true
)) {
    http_response_code(403);
    exit('403 Forbidden.');
}

$types = [
    'Full-time',
    'Part-time',
    'Probationary',
    'Contractual'
];

function employee_audit(
    PDO $pdo,
    int $actor,
    string $action,
    string $details
): void {
    $stmt = $pdo->prepare(
        'INSERT INTO audit_logs
         (actor_user_id, action, details)
         VALUES (?, ?, ?)'
    );
    $stmt->execute([
        $actor, $action, $details
    ]);
}

// PROCESS FORMS
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $message = 'Action failed.';
    $kind = 'error';

    try {
        if (!valid_csrf()) {
            throw new RuntimeException(
                'Invalid request. Refresh the page.'
            );
        }

        $action = (string) ($_POST['action'] ?? '');
        $actor = (int) $user['id'];

        // ADD / EDIT EMPLOYEE
        if ($action === 'save') {
            $employeeId = filter_var(
                $_POST['employee_id'] ?? '0',
                FILTER_VALIDATE_INT
            );

            if (
                $employeeId === false ||
                $employeeId < 0
            ) {
                throw new RuntimeException(
                    'Invalid employee ID.'
                );
            }

            $code = strtoupper(trim(
                (string) ($_POST['employee_code'] ?? '')
            ));

            $name = trim(
                (string) ($_POST['full_name'] ?? '')
            );

            $email = strtolower(trim(
                (string) ($_POST['email'] ?? '')
            ));

            $phone = trim(
                (string) ($_POST['phone'] ?? '')
            );

            $departmentId = filter_var(
                $_POST['department_id'] ?? null,
                FILTER_VALIDATE_INT
            );

            $positionId = filter_var(
                $_POST['position_id'] ?? null,
                FILTER_VALIDATE_INT
            );

            $hireDate = (string) (
                $_POST['hire_date'] ?? ''
            );

            $type = (string) (
                $_POST['employment_type'] ?? ''
            );

            $accountRaw = (string) (
                $_POST['user_id'] ?? ''
            );

            $accountId = $accountRaw === ''
                ? null
                : filter_var(
                    $accountRaw,
                    FILTER_VALIDATE_INT
                );

            if (!preg_match(
                '/^[A-Z0-9-]{3,20}$/',
                $code
            )) {
                throw new RuntimeException(
                    'Employee ID must be 3–20 letters, numbers or hyphens.'
                );
            }

            if (
                strlen($name) < 2 ||
                strlen($name) > 150
            ) {
                throw new RuntimeException(
                    'Enter a valid employee name.'
                );
            }

            if (
                !filter_var(
                    $email,
                    FILTER_VALIDATE_EMAIL
                ) ||
                strlen($email) > 150
            ) {
                throw new RuntimeException(
                    'Enter a valid employee email.'
                );
            }

            if (
                $phone !== '' &&
                !preg_match(
                    '/^[0-9+(). -]{7,25}$/',
                    $phone
                )
            ) {
                throw new RuntimeException(
                    'Enter a valid phone number.'
                );
            }

            if (!$departmentId || !$positionId) {
                throw new RuntimeException(
                    'Select department and position.'
                );
            }

            $date = DateTimeImmutable::createFromFormat(
                '!Y-m-d',
                $hireDate
            );

            if (
                !$date ||
                $date->format('Y-m-d') !== $hireDate
            ) {
                throw new RuntimeException(
                    'Enter a valid hire date.'
                );
            }

            if (!in_array($type, $types, true)) {
                throw new RuntimeException(
                    'Select a valid employment type.'
                );
            }

            if (
                $accountId === false ||
                (
                    $accountId !== null &&
                    $accountId < 1
                )
            ) {
                throw new RuntimeException(
                    'Invalid linked account.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT p.id
                 FROM positions p
                 JOIN departments d
                   ON d.id = p.department_id
                 WHERE p.id = ?
                   AND p.department_id = ?
                   AND d.is_active = 1'
            );

            $stmt->execute([
                $positionId,
                $departmentId
            ]);

            if (!$stmt->fetchColumn()) {
                throw new RuntimeException(
                    'Position does not belong to selected active department.'
                );
            }

            if ($employeeId > 0) {
                $stmt = $pdo->prepare(
                    'SELECT employment_status, deleted_at
                     FROM employees
                     WHERE id = ?
                     FOR UPDATE'
                );

                $stmt->execute([$employeeId]);
                $existing = $stmt->fetch();

                if (
                    !$existing ||
                    $existing['deleted_at'] !== null
                ) {
                    throw new RuntimeException(
                        'Employee archived or not found.'
                    );
                }

                if (
                    $existing['employment_status'] ===
                    'Inactive' &&
                    $accountId !== null
                ) {
                    throw new RuntimeException(
                        'Reactivate the employee before linking a login account.'
                    );
                }
            }

            if ($accountId !== null) {
                $stmt = $pdo->prepare(
                    'SELECT u.email
                     FROM users u
                     JOIN roles r ON r.id = u.role_id
                     WHERE u.id = ?
                       AND r.role_name = ?
                       AND u.deleted_at IS NULL'
                );
                $stmt->execute([
                    $accountId,
                    'employee'
                ]);

                $account = $stmt->fetch();

                if (
                    !$account ||
                    strcasecmp(
                        $account['email'],
                        $email
                    ) !== 0
                ) {
                    throw new RuntimeException(
                        'Linked Employee account must use the same email.'
                    );
                }

                $stmt = $pdo->prepare(
                    'SELECT id
                     FROM employees
                     WHERE user_id = ?
                       AND id <> ?'
                );
                $stmt->execute([
                    $accountId,
                    $employeeId
                ]);

                if ($stmt->fetchColumn()) {
                    throw new RuntimeException(
                        'Login already linked to another employee.'
                    );
                }
            }

            if ($employeeId === 0) {
                $stmt = $pdo->prepare(
                    'INSERT INTO employees
                     (
                        employee_code,
                        user_id,
                        full_name,
                        email,
                        phone,
                        department_id,
                        position_id,
                        hire_date,
                        employment_type,
                        created_by
                     )
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
                );

                $stmt->execute([
                    $code,
                    $accountId,
                    $name,
                    $email,
                    $phone !== '' ? $phone : null,
                    $departmentId,
                    $positionId,
                    $hireDate,
                    $type,
                    $actor
                ]);

                $employeeId =
                    (int) $pdo->lastInsertId();

                employee_audit(
                    $pdo,
                    $actor,
                    'EMPLOYEE_CREATE',
                    'Created employee ' . $code
                );

                $message = 'Employee added.';
            } else {
                $stmt = $pdo->prepare(
                    'UPDATE employees
                     SET employee_code = ?,
                         user_id = ?,
                         full_name = ?,
                         email = ?,
                         phone = ?,
                         department_id = ?,
                         position_id = ?,
                         hire_date = ?,
                         employment_type = ?
                     WHERE id = ?
                       AND deleted_at IS NULL'
                );

                $stmt->execute([
                    $code,
                    $accountId,
                    $name,
                    $email,
                    $phone !== '' ? $phone : null,
                    $departmentId,
                    $positionId,
                    $hireDate,
                    $type,
                    $employeeId
                ]);

                employee_audit(
                    $pdo,
                    $actor,
                    'EMPLOYEE_UPDATE',
                    'Updated employee ' . $code
                );

                $message = 'Employee updated.';
            }

            $pdo->commit();
            $kind = 'success';

        // ACTIVE / INACTIVE
        } elseif ($action === 'toggle_status') {
            $employeeId = filter_var(
                $_POST['employee_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$employeeId) {
                throw new RuntimeException(
                    'Invalid employee.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT employee_code,
                        employment_status,
                        user_id,
                        deleted_at
                 FROM employees
                 WHERE id = ?
                 FOR UPDATE'
            );
            $stmt->execute([$employeeId]);
            $employee = $stmt->fetch();

            if (
                !$employee ||
                $employee['deleted_at'] !== null
            ) {
                throw new RuntimeException(
                    'Employee archived or not found.'
                );
            }

            $newStatus =
                $employee['employment_status'] === 'Active'
                    ? 'Inactive'
                    : 'Active';

            $stmt = $pdo->prepare(
                'UPDATE employees
                 SET employment_status = ?
                 WHERE id = ?'
            );
            $stmt->execute([
                $newStatus,
                $employeeId
            ]);

            if (
                $newStatus === 'Inactive' &&
                $employee['user_id'] !== null
            ) {
                $stmt = $pdo->prepare(
                    "UPDATE users
                     SET is_active = 0
                     WHERE id = ?"
                );
                $stmt->execute([
                    (int) $employee['user_id']
                ]);
            }

            employee_audit(
                $pdo,
                $actor,
                'EMPLOYEE_STATUS',
                $employee['employee_code'] .
                ' changed to ' . $newStatus
            );

            $pdo->commit();
            $message = 'Employee marked ' . $newStatus;
            $kind = 'success';

        // THREE-DOT DELETE / RESTORE
        } elseif (
            $action === 'archive_employee' ||
            $action === 'restore_employee'
        ) {
            $employeeId = filter_var(
                $_POST['employee_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$employeeId) {
                throw new RuntimeException(
                    'Invalid employee.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT employee_code,
                        user_id,
                        deleted_at
                 FROM employees
                 WHERE id = ?
                 FOR UPDATE'
            );
            $stmt->execute([$employeeId]);
            $employee = $stmt->fetch();

            if (!$employee) {
                throw new RuntimeException(
                    'Employee not found.'
                );
            }

            if ($action === 'archive_employee') {
                if ($employee['deleted_at'] !== null) {
                    throw new RuntimeException(
                        'Employee already archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    "UPDATE employees
                     SET deleted_at = NOW(),
                         employment_status = 'Inactive'
                     WHERE id = ?"
                );
                $stmt->execute([$employeeId]);

                if ($employee['user_id'] !== null) {
                    $stmt = $pdo->prepare(
                        'UPDATE users
                         SET is_active = 0
                         WHERE id = ?'
                    );
                    $stmt->execute([
                        (int) $employee['user_id']
                    ]);
                }

                employee_audit(
                    $pdo,
                    $actor,
                    'ARCHIVE_EMPLOYEE',
                    'Archived employee #' . $employeeId .
                    ' (' . $employee['employee_code'] . ')'
                );

                $message =
                    'Employee deleted from active list; login disabled.';
            } else {
                if ($employee['deleted_at'] === null) {
                    throw new RuntimeException(
                        'Employee is not archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    "UPDATE employees
                     SET deleted_at = NULL,
                         employment_status = 'Inactive'
                     WHERE id = ?"
                );
                $stmt->execute([$employeeId]);

                employee_audit(
                    $pdo,
                    $actor,
                    'RESTORE_EMPLOYEE',
                    'Restored employee #' . $employeeId
                );

                $message =
                    'Employee restored as Inactive.';
            }

            $pdo->commit();
            $kind = 'success';
        } else {
            throw new RuntimeException(
                'Unknown action.'
            );
        }

    } catch (RuntimeException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $message = $e->getMessage();

    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log($e->getMessage());

        $message = $e->getCode() === '23000'
            ? 'Employee ID, email or linked account already exists. Restore archived employees instead of creating duplicates.'
            : 'Database error. Check setup.';

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log($e->getMessage());
        $message = 'Unexpected error.';
    }

    $_SESSION['employee_flash'] = [
        'kind' => $kind,
        'message' => $message
    ];

    header('Location: employees.php', true, 303);
    exit;
}

$flash = $_SESSION['employee_flash'] ?? null;
unset($_SESSION['employee_flash']);

$departments = $pdo->query(
    'SELECT id, department_name
     FROM departments
     WHERE is_active = 1
     ORDER BY department_name'
)->fetchAll();

$positions = $pdo->query(
    'SELECT id, department_id, position_name
     FROM positions
     ORDER BY position_name'
)->fetchAll();

$accounts = $pdo->query(
    "SELECT
        u.id,
        u.email,
        u.full_name,
        e.id AS linked_employee_id
     FROM users u
     JOIN roles r ON r.id = u.role_id
     LEFT JOIN employees e ON e.user_id = u.id
     WHERE r.role_name = 'employee'
       AND u.deleted_at IS NULL
     ORDER BY u.full_name"
)->fetchAll();

$employees = $pdo->query(
    'SELECT e.*,
            d.department_name,
            p.position_name
     FROM employees e
     JOIN departments d
       ON d.id = e.department_id
     JOIN positions p
       ON p.id = e.position_id
     ORDER BY e.id DESC'
)->fetchAll();

$total = 0;
$active = 0;
$linked = 0;

foreach ($employees as $e) {
    if ($e['deleted_at'] !== null) {
        continue;
    }

    $total++;

    if ($e['employment_status'] === 'Active') {
        $active++;
    }

    if ($e['user_id'] !== null) {
        $linked++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1">
<title>Employees | McDonald's San Pedro Bayan</title>
<link rel="stylesheet" href="../css/style.css">

<style>
.heading-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 15px;
    flex-wrap: wrap;
    margin: 26px 0;
}

.heading-row h1 {
    font-size: 32px;
    margin: 0 0 6px;
}

.stats {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin: 20px 0;
}

.stats strong {
    display: block;
    color: var(--green-dark);
    font-size: 30px;
    margin-top: 6px;
}

.action-btn {
    background: var(--green);
    color: white;
    border: 0;
    border-radius: 10px;
    padding: 12px 18px;
    cursor: pointer;
    font-weight: bold;
}

.small-btn {
    background: var(--light-green);
    color: var(--green-dark);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 11px;
    cursor: pointer;
    font-weight: bold;
}

.small-btn.warning,
.danger-action {
    background: #f9e7e7;
    color: #a23f3f;
}

.toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin: 20px 0;
}

.toolbar input,
.toolbar select {
    border: 1px solid var(--border);
    background: white;
    border-radius: 9px;
    padding: 11px;
    font-size: 15px;
    min-height: 45px;
}

.toolbar input {
    flex: 2;
    min-width: 190px;
}

.toolbar select {
    flex: 1;
    min-width: 140px;
}

.table-scroll {
    overflow: auto;
}

.employees-table {
    width: 100%;
    min-width: 860px;
    border-collapse: collapse;
}

.employees-table th,
.employees-table td {
    text-align: left;
    border-bottom: 1px solid var(--border);
    padding: 14px 10px;
    vertical-align: middle;
    font-size: 15px;
}

.employees-table th {
    color: var(--muted);
}

.employees-table small {
    display: block;
    color: var(--muted);
    margin-top: 5px;
}

.actions {
    display: flex;
    gap: 7px;
    align-items: center;
    flex-wrap: wrap;
}

.pill {
    display: inline-block;
    border-radius: 20px;
    padding: 6px 12px;
    font-weight: bold;
    font-size: 13px;
}

.pill.active {
    background: var(--light-green);
    color: var(--green-dark);
}

.pill.inactive {
    background: #f9e7e7;
    color: #a23f3f;
}

.pill.archived {
    background: #efe9df;
    color: #725a30;
}

.notice {
    padding: 13px 16px;
    border-radius: 10px;
    margin: 15px 0;
}

.notice.success {
    background: var(--light-green);
    color: var(--green-dark);
}

.notice.error {
    background: #f9e7e7;
    color: #a23f3f;
}

.employee-dialog {
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 24px;
    width: min(700px, 94vw);
    max-height: 90vh;
    overflow: auto;
    color: var(--text);
}

.employee-dialog::backdrop {
    background: rgba(15, 25, 18, .5);
}

.employee-dialog h2 {
    font-size: 25px;
    margin: 0 0 8px;
}

.form-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 2px 16px;
    margin-top: 14px;
}

.form-grid label {
    display: block;
    font-size: 15px;
    font-weight: 600;
    margin: 12px 0 6px;
}

.form-grid input,
.form-grid select {
    width: 100%;
    border: 1px solid var(--border);
    border-radius: 9px;
    min-height: 45px;
    padding: 10px;
    background: white;
}

.form-grid .wide {
    grid-column: 1 / -1;
}

.dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    margin-top: 20px;
}

.field-note {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.5;
    margin: 5px 0;
}

.dots-btn {
    width: 39px;
    height: 39px;
    border: 1px solid var(--border);
    border-radius: 9px;
    font-size: 24px;
    cursor: pointer;
    color: var(--green-dark);
    background: var(--light-green);
}

tr[hidden] {
    display: none;
}

@media (max-width: 850px) {
    .stats,
    .form-grid {
        grid-template-columns: 1fr;
    }
    .form-grid .wide {
        grid-column: auto;
    }
}
</style>
</head>

<body>
<div class="dashboard-layout">

<aside class="sidebar">
    <button class="toggle-btn" id="sidebarToggle"
            type="button">☰</button>
    <div class="sidebar-brand">HR &amp; Payroll</div>

    <a href="../dashboard.php" class="sidebar-item">
        <span class="sidebar-icon">⌂</span>
        <span class="sidebar-text">Dashboard</span>
    </a>

    <a href="employees.php" class="sidebar-item active">
        <span class="sidebar-icon">♙</span>
        <span class="sidebar-text">Employees</span>
    </a>

    <a href="recruitment.php" class="sidebar-item">
        <span class="sidebar-icon">▤</span>
        <span class="sidebar-text">Recruitment</span>
    </a>

    <a href="attendance.php" class="sidebar-item">
        <span class="sidebar-icon">◷</span>
        <span class="sidebar-text">Attendance</span>
    </a>

    <?php if ($user['role_name'] === 'administrator'): ?>
        <a href="users.php" class="sidebar-item">
            <span class="sidebar-icon">⚙</span>
            <span class="sidebar-text">Users &amp; Roles</span>
        </a>
    <?php endif; ?>

    <button class="sidebar-item"
            id="openLogout" type="button">
        <span class="sidebar-icon">⇥</span>
        <span class="sidebar-text">Log Out</span>
    </button>
</aside>

<main class="dashboard-main">
    <header class="topbar">
        <div>
            <strong>McDonald's San Pedro Bayan</strong>
            <div class="muted">
                HR &amp; Payroll Management System
            </div>
        </div>
        <span class="role-tag">
            <?= escape(ucwords(
                str_replace('_', ' ', $user['role_name'])
            )) ?>
        </span>
    </header>

    <div class="heading-row">
        <div>
            <h1>Employee Management</h1>
            <p class="muted">
                Maintain employee records and statuses.
            </p>
        </div>
        <button class="action-btn" type="button"
                id="addEmployee">
            + Add Employee
        </button>
    </div>

    <?php if ($flash): ?>
        <div class="notice <?= escape($flash['kind']) ?>">
            <?= escape($flash['message']) ?>
        </div>
    <?php endif; ?>

    <div class="stats">
        <div class="dashboard-card">
            <span class="muted">Total Employees</span>
            <strong><?= $total ?></strong>
        </div>

        <div class="dashboard-card">
            <span class="muted">Active Employees</span>
            <strong><?= $active ?></strong>
        </div>

        <div class="dashboard-card">
            <span class="muted">
                Linked Login Accounts
            </span>
            <strong><?= $linked ?></strong>
        </div>
    </div>

    <section class="dashboard-card">
        <h2>Employee Directory</h2>

        <div class="toolbar">
            <input
                type="search"
                id="search"
                placeholder="Search employee..."
                aria-label="Search employees">

            <select id="departmentFilter">
                <option value="">All Departments</option>

                <?php foreach ($departments as $d): ?>
                    <option value="<?= (int) $d['id'] ?>">
                        <?= escape($d['department_name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <select id="statusFilter">
                <option value="">All Statuses</option>
                <option value="Active">Active</option>
                <option value="Inactive">Inactive</option>
                <option value="Archived">Archived</option>
            </select>
        </div>

        <div class="table-scroll">
            <table class="employees-table"
                   id="employeesTable">
                <thead>
                    <tr>
                        <th>Employee</th>
                        <th>Department</th>
                        <th>Position</th>
                        <th>Hire Date</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>

                <tbody>
                <?php foreach ($employees as $e): ?>
                    <?php
                    $archived =
                        $e['deleted_at'] !== null;

                    $data = json_encode([
                        'id' => (int) $e['id'],
                        'employee_code' =>
                            $e['employee_code'],
                        'full_name' =>
                            $e['full_name'],
                        'email' => $e['email'],
                        'phone' => $e['phone'] ?? '',
                        'department_id' =>
                            (int) $e['department_id'],
                        'position_id' =>
                            (int) $e['position_id'],
                        'hire_date' => $e['hire_date'],
                        'employment_type' =>
                            $e['employment_type'],
                        'user_id' => $e['user_id'] === null
                            ? ''
                            : (string) $e['user_id']
                    ], JSON_HEX_TAG | JSON_HEX_AMP |
                       JSON_HEX_APOS | JSON_HEX_QUOT);
                    ?>

                    <tr
                        data-dept="<?= (int) $e['department_id'] ?>"
                        data-status="<?= escape(
                            $e['employment_status']
                        ) ?>"
                        data-archived="<?= $archived
                            ? '1'
                            : '0' ?>">

                        <td>
                            <strong>
                                <?= escape($e['full_name']) ?>
                            </strong>
                            <small>
                                <?= escape(
                                    $e['employee_code']
                                ) ?>
                                ·
                                <?= escape($e['email']) ?>
                            </small>
                        </td>

                        <td>
                            <?= escape($e['department_name']) ?>
                        </td>

                        <td>
                            <?= escape($e['position_name']) ?>
                        </td>

                        <td>
                            <?= escape($e['hire_date']) ?>
                        </td>

                        <td>
                            <span class="pill <?= $archived
                                ? 'archived'
                                : strtolower(
                                    $e['employment_status']
                                ) ?>">
                                <?= $archived
                                    ? 'Archived'
                                    : escape(
                                        $e['employment_status']
                                    ) ?>
                            </span>
                        </td>

                        <td>
                            <div class="actions">

                                <?php if (!$archived): ?>
                                    <button
                                        type="button"
                                        class="small-btn"
                                        data-record="<?= escape(
                                            $data
                                        ) ?>"
                                        onclick="editEmployee(this)">
                                        Edit
                                    </button>

                                    <button
                                        type="button"
                                        class="small-btn <?= $e['employment_status'] === 'Active'
                                            ? 'warning'
                                            : '' ?>"
                                        data-id="<?= (int) $e['id'] ?>"
                                        data-name="<?= escape(
                                            $e['full_name']
                                        ) ?>"
                                        data-status="<?= escape(
                                            $e['employment_status']
                                        ) ?>"
                                        onclick="confirmStatus(this)">
                                        <?= $e['employment_status'] === 'Active'
                                            ? 'Deactivate'
                                            : 'Reactivate' ?>
                                    </button>
                                <?php endif; ?>

                                <button
                                    type="button"
                                    class="dots-btn"
                                    aria-label="Employee actions"
                                    data-id="<?= (int) $e['id'] ?>"
                                    data-name="<?= escape(
                                        $e['full_name']
                                    ) ?>"
                                    data-archived="<?= $archived
                                        ? '1'
                                        : '0' ?>"
                                    onclick="openEmployeeActions(this)">
                                    ⋮
                                </button>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <p class="muted" id="noResults" hidden>
            No matching employees found.
        </p>

        <p class="muted">
            Deleted employees are shown under Archived.
            Restore an existing record instead of creating
            another employee with the same email or ID.
        </p>
    </section>
</main>
</div>

<!-- ADD / EDIT EMPLOYEE -->
<dialog class="employee-dialog" id="employeeDialog">
    <h2 id="employeeDialogTitle">Add Employee</h2>

    <p class="muted">
        Employee details only. Salary is restricted
        to the Payroll module.
    </p>

    <form action="employees.php" method="POST"
          id="employeeForm">

        <input type="hidden" name="csrf_token"
               value="<?= escape(csrf_token()) ?>">
        <input type="hidden" name="action"
               value="save">
        <input type="hidden" name="employee_id"
               id="employeeId" value="0">

        <div class="form-grid">
            <div>
                <label for="employeeCode">Employee ID</label>
                <input id="employeeCode"
                       name="employee_code"
                       maxlength="20" required>
            </div>

            <div>
                <label for="employeeName">Full Name</label>
                <input id="employeeName"
                       name="full_name"
                       maxlength="150" required>
            </div>

            <div>
                <label for="employeeEmail">Email</label>
                <input id="employeeEmail"
                       name="email" type="email"
                       maxlength="150" required>
            </div>

            <div>
                <label for="employeePhone">
                    Phone (optional)
                </label>
                <input id="employeePhone"
                       name="phone" maxlength="25">
            </div>

            <div>
                <label for="employeeDepartment">
                    Department
                </label>
                <select id="employeeDepartment"
                        name="department_id" required>
                    <option value="">
                        Select Department
                    </option>

                    <?php foreach ($departments as $d): ?>
                        <option value="<?= (int) $d['id'] ?>">
                            <?= escape(
                                $d['department_name']
                            ) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div>
                <label for="employeePosition">
                    Position
                </label>
                <select id="employeePosition"
                        name="position_id" required>
                    <option value="">Select Position</option>

                    <?php foreach ($positions as $p): ?>
                        <option
                            value="<?= (int) $p['id'] ?>"
                            data-dept="<?= (int) $p['department_id'] ?>">
                            <?= escape(
                                $p['position_name']
                            ) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div>
                <label for="employeeHireDate">
                    Hire Date
                </label>
                <input type="date"
                       id="employeeHireDate"
                       name="hire_date" required>
            </div>

            <div>
                <label for="employeeType">
                    Employment Type
                </label>
                <select id="employeeType"
                        name="employment_type" required>
                    <?php foreach ($types as $type): ?>
                        <option value="<?= escape($type) ?>">
                            <?= escape($type) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="wide">
                <label for="employeeAccount">
                    Linked Employee Login (optional)
                </label>

                <select id="employeeAccount" name="user_id">
                    <option value="">
                        No Account Linked
                    </option>

                    <?php foreach ($accounts as $a): ?>
                        <option
                            value="<?= (int) $a['id'] ?>"
                            data-linked="<?= (int) (
                                $a['linked_employee_id'] ?? 0
                            ) ?>">
                            <?= escape(
                                $a['full_name'] .
                                ' — ' . $a['email']
                            ) ?>
                        </option>
                    <?php endforeach; ?>
                </select>

                <p class="field-note">
                    Employee login must have the same email.
                    Create accounts from Users &amp; Roles.
                </p>
            </div>
        </div>

        <div class="dialog-actions">
            <button type="button" class="dialog-btn"
                    onclick="employeeDialog.close()">
                Cancel
            </button>

            <button type="submit" class="action-btn">
                Save Employee
            </button>
        </div>
    </form>
</dialog>

<!-- ACTIVE / INACTIVE CONFIRMATION -->
<dialog class="confirm-dialog" id="statusDialog">
    <h3>Confirm Employment Status</h3>
    <p id="statusMessage"></p>
    <p class="muted" id="statusNote"></p>

    <div class="dialog-actions">
        <button type="button" class="dialog-btn"
                onclick="statusDialog.close()">
            Cancel
        </button>

        <form method="POST" action="employees.php">
            <input type="hidden" name="csrf_token"
                   value="<?= escape(csrf_token()) ?>">
            <input type="hidden" name="action"
                   value="toggle_status">
            <input type="hidden" name="employee_id"
                   id="statusEmployeeId">

            <button type="submit"
                    class="dialog-btn confirm">
                Confirm
            </button>
        </form>
    </div>
</dialog>

<!-- THREE-DOT MENU -->
<dialog class="confirm-dialog" id="employeeActionsDialog">
    <h3>Employee Actions</h3>
    <p id="employeeActionsMessage"></p>
    <p class="muted" id="employeeActionsNote"></p>

    <div class="dialog-actions">
        <button type="button" class="dialog-btn"
                onclick="employeeActionsDialog.close()">
            Cancel
        </button>

        <button type="button"
                id="employeeActionsButton"
                class="dialog-btn danger-action">
            Delete
        </button>
    </div>
</dialog>

<!-- DELETE / RESTORE CONFIRMATION -->
<dialog class="confirm-dialog" id="employeeDeleteDialog">
    <h3 id="employeeDeleteTitle">
        Delete Employee?
    </h3>

    <p id="employeeDeleteMessage"></p>

    <div class="dialog-actions">
        <button type="button" class="dialog-btn"
                onclick="employeeDeleteDialog.close()">
            Cancel
        </button>

        <form method="POST" action="employees.php">
            <input type="hidden" name="csrf_token"
                   value="<?= escape(csrf_token()) ?>">
            <input type="hidden" name="action"
                   id="employeeDeleteAction">
            <input type="hidden" name="employee_id"
                   id="employeeDeleteId">

            <button type="submit"
                    class="dialog-btn confirm"
                    id="employeeDeleteSubmit">
                Yes, Delete
            </button>
        </form>
    </div>
</dialog>

<!-- LOGOUT -->
<dialog class="confirm-dialog" id="logoutDialog">
    <h3>Confirm Logout</h3>
    <p>Are you sure you want to log out?</p>

    <div class="dialog-actions">
        <button type="button" class="dialog-btn"
                onclick="logoutDialog.close()">
            Cancel
        </button>

        <form action="../logout.php" method="POST">
            <input type="hidden" name="csrf_token"
                   value="<?= escape(csrf_token()) ?>">

            <button type="submit"
                    class="dialog-btn confirm">
                Log Out
            </button>
        </form>
    </div>
</dialog>

<script>
const employeeDialog =
    document.getElementById('employeeDialog');

const employeeForm =
    document.getElementById('employeeForm');

const departmentSelect =
    document.getElementById('employeeDepartment');

const positionSelect =
    document.getElementById('employeePosition');

const accountSelect =
    document.getElementById('employeeAccount');

const statusDialog =
    document.getElementById('statusDialog');

const employeeActionsDialog =
    document.getElementById('employeeActionsDialog');

const employeeDeleteDialog =
    document.getElementById('employeeDeleteDialog');

const logoutDialog =
    document.getElementById('logoutDialog');

const positions = Array.from(positionSelect.options)
    .filter(option => option.value)
    .map(option => ({
        id: option.value,
        name: option.textContent,
        department: option.dataset.dept
    }));

function updatePositions(selectedId = '') {
    positionSelect.replaceChildren();

    positionSelect.add(new Option(
        departmentSelect.value
            ? 'Select Position'
            : 'Select Department First',
        ''
    ));

    const matching = positions.filter(
        item =>
            item.department === departmentSelect.value
    );

    matching.forEach(item => {
        positionSelect.add(
            new Option(item.name, item.id)
        );
    });

    positionSelect.disabled = matching.length === 0;

    if (selectedId) {
        positionSelect.value = String(selectedId);
    }
}

function updateAccounts(currentEmployeeId) {
    for (const option of accountSelect.options) {
        if (!option.value) continue;

        const linked =
            Number(option.dataset.linked || 0);

        option.disabled =
            linked !== 0 &&
            linked !== Number(currentEmployeeId);
    }
}

departmentSelect.addEventListener('change', () => {
    updatePositions();
});

document.getElementById('addEmployee')
    .addEventListener('click', () => {
        employeeForm.reset();

        document.getElementById(
            'employeeId'
        ).value = '0';

        document.getElementById(
            'employeeDialogTitle'
        ).textContent = 'Add Employee';

        updatePositions();
        updateAccounts(0);

        employeeDialog.showModal();
    });

function editEmployee(button) {
    const e = JSON.parse(button.dataset.record);

    employeeForm.reset();

    document.getElementById(
        'employeeDialogTitle'
    ).textContent = 'Edit Employee';

    document.getElementById(
        'employeeId'
    ).value = e.id;

    document.getElementById(
        'employeeCode'
    ).value = e.employee_code;

    document.getElementById(
        'employeeName'
    ).value = e.full_name;

    document.getElementById(
        'employeeEmail'
    ).value = e.email;

    document.getElementById(
        'employeePhone'
    ).value = e.phone;

    departmentSelect.value = String(e.department_id);

    updatePositions(e.position_id);

    document.getElementById(
        'employeeHireDate'
    ).value = e.hire_date;

    document.getElementById(
        'employeeType'
    ).value = e.employment_type;

    updateAccounts(e.id);

    accountSelect.value = String(e.user_id || '');

    employeeDialog.showModal();
}

function confirmStatus(button) {
    const deactivate =
        button.dataset.status === 'Active';

    document.getElementById(
        'statusEmployeeId'
    ).value = button.dataset.id;

    document.getElementById(
        'statusMessage'
    ).textContent =
        'Are you sure you want to ' +
        (deactivate ? 'deactivate ' : 'reactivate ') +
        button.dataset.name + '?';

    document.getElementById(
        'statusNote'
    ).textContent = deactivate
        ? 'Linked Employee login will also be disabled.'
        : 'Disabled login must be reactivated separately by Administrator.';

    statusDialog.showModal();
}

let selectedEmployee = null;

function openEmployeeActions(button) {
    selectedEmployee = {
        id: button.dataset.id,
        name: button.dataset.name,
        archived: button.dataset.archived === '1'
    };

    document.getElementById(
        'employeeActionsMessage'
    ).textContent = selectedEmployee.name;

    document.getElementById(
        'employeeActionsNote'
    ).textContent = selectedEmployee.archived
        ? 'Restore as Inactive. Login will remain disabled.'
        : 'Employee will be archived. History is retained and linked login is disabled.';

    document.getElementById(
        'employeeActionsButton'
    ).textContent = selectedEmployee.archived
        ? 'Restore'
        : 'Delete';

    employeeActionsDialog.showModal();
}

document.getElementById('employeeActionsButton')
    .addEventListener('click', () => {
        if (!selectedEmployee) return;

        document.getElementById(
            'employeeDeleteId'
        ).value = selectedEmployee.id;

        document.getElementById(
            'employeeDeleteAction'
        ).value = selectedEmployee.archived
            ? 'restore_employee'
            : 'archive_employee';

        document.getElementById(
            'employeeDeleteTitle'
        ).textContent = selectedEmployee.archived
            ? 'Restore Employee?'
            : 'Delete Employee?';

        document.getElementById(
            'employeeDeleteMessage'
        ).textContent =
            (selectedEmployee.archived
                ? 'Restore '
                : 'Archive ') +
            selectedEmployee.name + '?';

        document.getElementById(
            'employeeDeleteSubmit'
        ).textContent = selectedEmployee.archived
            ? 'Yes, Restore'
            : 'Yes, Delete';

        employeeActionsDialog.close();
        employeeDeleteDialog.showModal();
    });

function filterEmployees() {
    const search =
        document.getElementById('search')
            .value.toLowerCase().trim();

    const dept =
        document.getElementById('departmentFilter').value;

    const status =
        document.getElementById('statusFilter').value;

    let visible = 0;

    document.querySelectorAll(
        '#employeesTable tbody tr'
    ).forEach(row => {
        const archived =
            row.dataset.archived === '1';

        const statusMatches = status === 'Archived'
            ? archived
            : !archived && (
                !status ||
                row.dataset.status === status
            );

        const show =
            row.textContent.toLowerCase().includes(search) &&
            (!dept || row.dataset.dept === dept) &&
            statusMatches;

        row.hidden = !show;

        if (show) visible++;
    });

    document.getElementById(
        'noResults'
    ).hidden = visible > 0;
}

['search', 'departmentFilter', 'statusFilter']
    .forEach(id => {
        document.getElementById(id)
            .addEventListener(
                id === 'search' ? 'input' : 'change',
                filterEmployees
            );
    });

filterEmployees();

document.getElementById('sidebarToggle')
    .addEventListener('click', () => {
        document.body.classList.toggle('collapsed');
    });

document.getElementById('openLogout')
    .addEventListener('click', () => {
        logoutDialog.showModal();
    });
</script>

<?php require __DIR__ . '/../includes/account_widget.php'; ?>
</body>

</html>
