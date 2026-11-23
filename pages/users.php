
<?php
require_once __DIR__ . '/../includes/auth.php';

$user = current_user();

if (!$user) {
    header('Location: ../index.php');
    exit;
}

if ($user['role_name'] !== 'administrator') {
    http_response_code(403);
    exit('403 Forbidden: Administrator only.');
}

$roles = [
    'administrator' => 'Administrator',
    'hr_officer' => 'HR Officer',
    'department_manager' => 'Department Manager',
    'payroll_officer' => 'Payroll Officer',
    'finance_officer' => 'Finance Officer',
    'employee' => 'Employee'
];

function users_audit(
    PDO $pdo,
    int $actor,
    int $target,
    string $action,
    string $detail
): void {
    $stmt = $pdo->prepare(
        'INSERT INTO audit_logs
         (actor_user_id, target_user_id, action, details)
         VALUES (?, ?, ?, ?)'
    );

    $stmt->execute([
        $actor,
        $target,
        $action,
        $detail
    ]);
}

// HANDLE ACCOUNT ACTIONS
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $kind = 'error';
    $message = 'Unable to complete action.';

    try {
        if (!valid_csrf()) {
            throw new RuntimeException(
                'Invalid request. Refresh the page.'
            );
        }

        $action = (string) ($_POST['action'] ?? '');
        $actor = (int) $user['id'];

        // CREATE ACCOUNT
        if ($action === 'create') {
            $name = trim(
                (string) ($_POST['full_name'] ?? '')
            );

            $email = strtolower(trim(
                (string) ($_POST['email'] ?? '')
            ));

            $password = (string) (
                $_POST['password'] ?? ''
            );

            $role = (string) ($_POST['role'] ?? '');

            if (
                strlen($name) < 2 ||
                strlen($name) > 150
            ) {
                throw new RuntimeException(
                    'Enter a valid full name.'
                );
            }

            if (
                !filter_var($email, FILTER_VALIDATE_EMAIL) ||
                strlen($email) > 150
            ) {
                throw new RuntimeException(
                    'Enter a valid email.'
                );
            }

            if (!isset($roles[$role])) {
                throw new RuntimeException(
                    'Select a valid role.'
                );
            }

            if (
                strlen($password) < 12 ||
                strlen($password) > 72 ||
                !preg_match('/[A-Z]/', $password) ||
                !preg_match('/[a-z]/', $password) ||
                !preg_match('/[0-9]/', $password) ||
                !preg_match('/[^A-Za-z0-9]/', $password)
            ) {
                throw new RuntimeException(
                    'Password needs 12–72 characters, uppercase, lowercase, number and symbol.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT id
                 FROM roles
                 WHERE role_name = ?
                 LIMIT 1'
            );

            $stmt->execute([$role]);
            $roleId = $stmt->fetchColumn();

            if (!$roleId) {
                throw new RuntimeException(
                    'Role missing from database.'
                );
            }

            $stmt = $pdo->prepare(
                'INSERT INTO users
                 (
                    full_name,
                    email,
                    password_hash,
                    role_id,
                    is_active
                 )
                 VALUES (?, ?, ?, ?, 1)'
            );

            $stmt->execute([
                $name,
                $email,
                password_hash(
                    $password,
                    PASSWORD_DEFAULT
                ),
                $roleId
            ]);

            $target = (int) $pdo->lastInsertId();

            users_audit(
                $pdo,
                $actor,
                $target,
                'CREATE_USER',
                'Created internal account with role ' . $role
            );

            $pdo->commit();

            $message = 'Account created successfully.';
            $kind = 'success';

        // ROLE, STATUS, DELETE
        } elseif (in_array(
            $action,
            ['update_role', 'toggle_status', 'delete_user'],
            true
        )) {
            $target = filter_var(
                $_POST['user_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$target) {
                throw new RuntimeException(
                    'Invalid account.'
                );
            }

            if ((int) $target === $actor) {
                throw new RuntimeException(
                    'You cannot change or delete your own Administrator account.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT
                    u.id,
                    u.full_name,
                    u.is_active,
                    u.deleted_at,
                    r.role_name
                 FROM users u
                 JOIN roles r
                   ON r.id = u.role_id
                 WHERE u.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$target]);
            $account = $stmt->fetch();

            if (
                !$account ||
                $account['deleted_at'] !== null
            ) {
                throw new RuntimeException(
                    'Account not found or already deleted.'
                );
            }

            // CHANGE ROLE
            if ($action === 'update_role') {
                $newRole = (string) (
                    $_POST['role'] ?? ''
                );

                if (
                    $account['role_name'] === 'applicant'
                ) {
                    throw new RuntimeException(
                        'Applicant conversion must go through Recruitment.'
                    );
                }

                if (!isset($roles[$newRole])) {
                    throw new RuntimeException(
                        'Invalid internal role.'
                    );
                }

                if (
                    $account['role_name'] === $newRole
                ) {
                    throw new RuntimeException(
                        'No role change selected.'
                    );
                }

                // Protect linked employee accounts
                $stmt = $pdo->prepare(
                    'SELECT id
                     FROM employees
                     WHERE user_id = ?
                     LIMIT 1'
                );

                $stmt->execute([$target]);

                if (
                    $stmt->fetchColumn() &&
                    $newRole !== 'employee'
                ) {
                    throw new RuntimeException(
                        'Unlink this account from its employee record before changing its role.'
                    );
                }

                $stmt = $pdo->prepare(
                    'SELECT id
                     FROM roles
                     WHERE role_name = ?
                     LIMIT 1'
                );

                $stmt->execute([$newRole]);
                $roleId = $stmt->fetchColumn();

                if (!$roleId) {
                    throw new RuntimeException(
                        'Role missing.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE users
                     SET role_id = ?
                     WHERE id = ?'
                );

                $stmt->execute([
                    $roleId,
                    $target
                ]);

                users_audit(
                    $pdo,
                    $actor,
                    (int) $target,
                    'CHANGE_ROLE',
                    $account['role_name'] .
                    ' → ' . $newRole
                );

                $message = 'Role changed successfully.';

            // ACTIVATE / DEACTIVATE
            } elseif ($action === 'toggle_status') {
                $active =
                    (int) $account['is_active'] === 1
                        ? 0
                        : 1;

                if (
                    $active === 1 &&
                    $account['role_name'] === 'employee'
                ) {
                    $stmt = $pdo->prepare(
                        "SELECT id
                         FROM employees
                         WHERE user_id = ?
                           AND employment_status = 'Inactive'
                         LIMIT 1"
                    );

                    $stmt->execute([$target]);

                    if ($stmt->fetchColumn()) {
                        throw new RuntimeException(
                            'Reactivate the employee record first.'
                        );
                    }
                }

                $stmt = $pdo->prepare(
                    'UPDATE users
                     SET is_active = ?
                     WHERE id = ?'
                );

                $stmt->execute([
                    $active,
                    $target
                ]);

                users_audit(
                    $pdo,
                    $actor,
                    (int) $target,
                    'ACCOUNT_STATUS',
                    $active
                        ? 'Activated account'
                        : 'Deactivated account'
                );

                $message = $active
                    ? 'Account activated.'
                    : 'Account deactivated.';

            // DELETE ACCOUNT (SOFT DELETE)
            } else {
                $stmt = $pdo->prepare(
                    'UPDATE users
                     SET is_active = 0,
                         deleted_at = NOW()
                     WHERE id = ?
                       AND deleted_at IS NULL'
                );

                $stmt->execute([$target]);

                if ($stmt->rowCount() !== 1) {
                    throw new RuntimeException(
                        'Account could not be deleted.'
                    );
                }

                users_audit(
                    $pdo,
                    $actor,
                    (int) $target,
                    'DELETE_USER',
                    'Archived and disabled account #' .
                        $target
                );

                $message =
                    'Account deleted from the active list and login disabled.';
            }

            $pdo->commit();
            $kind = 'success';

        } else {
            throw new RuntimeException('Unknown action.');
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
            ? 'Email is already registered (including archived accounts) or a database constraint was not met.'
            : 'Database error. Check the tables.';

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log($e->getMessage());

        $message = 'Unexpected error. Please try again.';
    }

    $_SESSION['users_flash'] = [
        'kind' => $kind,
        'message' => $message
    ];

    header('Location: users.php', true, 303);
    exit;
}

// LOAD DATA
$flash = $_SESSION['users_flash'] ?? null;
unset($_SESSION['users_flash']);

$accounts = $pdo->query(
    'SELECT
        u.id,
        u.full_name,
        u.email,
        u.is_active,
        u.created_at,
        r.role_name
     FROM users u
     JOIN roles r
       ON r.id = u.role_id
     WHERE u.deleted_at IS NULL
     ORDER BY u.id DESC'
)->fetchAll();

$total = count($accounts);
$active = 0;
$applicants = 0;

foreach ($accounts as $a) {
    if ((int) $a['is_active'] === 1) {
        $active++;
    }

    if ($a['role_name'] === 'applicant') {
        $applicants++;
    }
}

$events = $pdo->query(
    'SELECT
        a.action,
        a.details,
        a.created_at,
        actor.full_name AS actor_name,
        target.full_name AS target_name
     FROM audit_logs a
     JOIN users actor
       ON actor.id = a.actor_user_id
     LEFT JOIN users target
       ON target.id = a.target_user_id
     ORDER BY a.id DESC
     LIMIT 10'
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Users &amp; Roles | McDonald's San Pedro Bayan</title>
<link rel="stylesheet" href="../css/style.css">

<style>
.users-title {
    margin: 28px 0;
}

.users-title h1 {
    font-size: 32px;
    margin: 0 0 7px;
}

.users-stats {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin-bottom: 20px;
}

.users-stats strong {
    display: block;
    font-size: 30px;
    color: var(--green-dark);
    margin-top: 7px;
}

.users-panel {
    margin-bottom: 20px;
}

.users-panel h2 {
    font-size: 22px;
    margin: 0 0 15px;
}

.user-form {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.user-field label {
    display: block;
    font-weight: 600;
    margin-bottom: 7px;
}

.user-field input,
.user-field select {
    width: 100%;
    min-height: 46px;
    padding: 11px;
    border: 1px solid var(--border);
    border-radius: 9px;
    background: white;
    color: var(--text);
}

.user-wide {
    grid-column: 1 / -1;
}

.user-primary {
    background: var(--green);
    color: white;
    border: 0;
    border-radius: 9px;
    padding: 12px 19px;
    font-weight: bold;
    font-size: 16px;
    cursor: pointer;
}

.user-primary:hover {
    background: var(--green-dark);
}

.user-search {
    min-height: 45px;
    width: min(100%, 380px);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 10px 12px;
    margin-bottom: 12px;
}

.user-scroll {
    overflow-x: auto;
}

.user-table {
    width: 100%;
    min-width: 920px;
    border-collapse: collapse;
}

.user-table th,
.user-table td {
    text-align: left;
    padding: 14px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    font-size: 15px;
}

.user-table th {
    color: var(--muted);
}

.user-table small {
    display: block;
    color: var(--muted);
    margin-top: 4px;
}

.user-role-form {
    display: flex;
    gap: 8px;
    align-items: center;
}

.user-role-form select {
    min-height: 41px;
    padding: 8px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: white;
}

.user-actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.small-btn {
    border: 1px solid var(--border);
    background: var(--light-green);
    color: var(--green-dark);
    padding: 9px 12px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
}

.small-btn.danger {
    background: #f9e7e7;
    color: #a23f3f;
}

.user-tag {
    display: inline-block;
    padding: 7px 12px;
    border-radius: 20px;
    background: var(--light-green);
    color: var(--green-dark);
    font-size: 13px;
    font-weight: bold;
}

.user-tag.inactive {
    background: #f9e7e7;
    color: #a23f3f;
}

.user-notice {
    padding: 14px;
    border-radius: 10px;
    margin-bottom: 17px;
}

.user-notice.success {
    background: var(--light-green);
    color: var(--green-dark);
}

.user-notice.error {
    background: #f9e7e7;
    color: #a23f3f;
}

.user-note {
    font-size: 14px;
    color: var(--muted);
    line-height: 1.6;
}

.activity li {
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
}

tr[hidden] {
    display: none;
}

@media (max-width: 740px) {
    .users-stats,
    .user-form {
        grid-template-columns: 1fr;
    }

    .user-wide {
        grid-column: auto;
    }
}
</style>
</head>

<body>
<div class="dashboard-layout">

    <aside class="sidebar">
        <button
            class="toggle-btn"
            id="sidebarToggle"
            type="button"
            aria-label="Toggle sidebar"
        >☰</button>

        <div class="sidebar-brand">HR &amp; Payroll</div>

        <a class="sidebar-item" href="../dashboard.php">
            <span class="sidebar-icon">⌂</span>
            <span class="sidebar-text">Dashboard</span>
        </a>

        <a class="sidebar-item" href="employees.php">
            <span class="sidebar-icon">♙</span>
            <span class="sidebar-text">Employees</span>
        </a>

        <a class="sidebar-item" href="recruitment.php">
            <span class="sidebar-icon">▤</span>
            <span class="sidebar-text">Recruitment</span>
        </a>

        <a class="sidebar-item" href="attendance.php">
            <span class="sidebar-icon">◷</span>
            <span class="sidebar-text">Attendance</span>
        </a>

        <a class="sidebar-item active" href="users.php">
            <span class="sidebar-icon">⚙</span>
            <span class="sidebar-text">Users &amp; Roles</span>
        </a>

        <button
            class="sidebar-item"
            id="openLogout"
            type="button"
        >
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

            <span class="role-tag">Administrator</span>
        </header>

        <div class="users-title">
            <h1>Users &amp; Roles</h1>
            <p class="muted">
                Manage accounts, permissions, and account status.
            </p>
        </div>

        <?php if ($flash): ?>
            <div class="user-notice <?= escape($flash['kind']) ?>">
                <?= escape($flash['message']) ?>
            </div>
        <?php endif; ?>

        <div class="users-stats">

            <div class="dashboard-card">
                <span class="muted">All User Accounts</span>
                <strong><?= $total ?></strong>
            </div>

            <div class="dashboard-card">
                <span class="muted">Active Accounts</span>
                <strong><?= $active ?></strong>
            </div>

            <div class="dashboard-card">
                <span class="muted">Applicant Accounts</span>
                <strong><?= $applicants ?></strong>
            </div>

        </div>

        <!-- CREATE ACCOUNT -->
        <section class="dashboard-card users-panel">
            <h2>Create Internal Account</h2>

            <p class="user-note">
                Only Administrators can create internal
                accounts. New job applicants must use the
                public Sign Up page.
            </p>

            <form
                action="users.php"
                method="POST"
                class="user-form"
            >
                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= escape(csrf_token()) ?>"
                >

                <input
                    type="hidden"
                    name="action"
                    value="create"
                >

                <div class="user-field">
                    <label for="fullName">Full Name</label>
                    <input
                        id="fullName"
                        name="full_name"
                        maxlength="150"
                        required
                    >
                </div>

                <div class="user-field">
                    <label for="email">Email</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        maxlength="150"
                        required
                    >
                </div>

                <div class="user-field">
                    <label for="role">Role</label>

                    <select id="role" name="role" required>
                        <?php foreach ($roles as $key => $label): ?>
                            <option value="<?= escape($key) ?>">
                                <?= escape($label) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="user-field">
                    <label for="password">Temporary Password</label>

                    <input
                        id="password"
                        name="password"
                        type="password"
                        minlength="12"
                        maxlength="72"
                        autocomplete="new-password"
                        required
                    >
                </div>

                <div class="user-wide">
                    <p class="user-note">
                        Password must be 12–72 characters
                        with uppercase, lowercase, number,
                        and symbol. Use test credentials only;
                        forced first-login password change
                        is not implemented yet.
                    </p>

                    <button
                        type="submit"
                        class="user-primary"
                    >
                        Create Account
                    </button>
                </div>
            </form>
        </section>

        <!-- ALL USER ACCOUNTS -->
        <section class="dashboard-card users-panel">
            <h2>All User Accounts</h2>

            <input
                type="search"
                class="user-search"
                id="userSearch"
                placeholder="Search name, email or role..."
                aria-label="Search user accounts"
            >

            <div class="user-scroll">
                <table class="user-table" id="usersTable">

                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Change Role</th>
                            <th>Actions</th>
                        </tr>
                    </thead>

                    <tbody>
                    <?php foreach ($accounts as $a): ?>

                        <?php
                        $self =
                            (int) $a['id'] ===
                            (int) $user['id'];
                        ?>

                        <tr>
                            <td>
                                <strong>
                                    <?= escape($a['full_name']) ?>
                                </strong>

                                <small>
                                    <?= escape($a['email']) ?>
                                </small>
                            </td>

                            <td>
                                <?= escape(ucwords(
                                    str_replace(
                                        '_',
                                        ' ',
                                        $a['role_name']
                                    )
                                )) ?>
                            </td>

                            <td>
                                <span class="user-tag <?= (int) $a['is_active'] ? '' : 'inactive' ?>">
                                    <?= (int) $a['is_active']
                                        ? 'Active'
                                        : 'Inactive' ?>
                                </span>
                            </td>

                            <td>
                                <?php if ($self): ?>
                                    <span class="user-note">
                                        Current account
                                    </span>

                                <?php elseif (
                                    $a['role_name'] === 'applicant'
                                ): ?>
                                    <span class="user-note">
                                        Recruitment only
                                    </span>

                                <?php else: ?>
                                    <form
                                        action="users.php"
                                        method="POST"
                                        class="user-role-form"
                                    >
                                        <input
                                            type="hidden"
                                            name="csrf_token"
                                            value="<?= escape(csrf_token()) ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="action"
                                            value="update_role"
                                        >

                                        <input
                                            type="hidden"
                                            name="user_id"
                                            value="<?= (int) $a['id'] ?>"
                                        >

                                        <select
                                            name="role"
                                            aria-label="Role for <?= escape($a['full_name']) ?>"
                                        >
                                            <?php foreach (
                                                $roles as $key => $label
                                            ): ?>
                                                <option
                                                    value="<?= escape($key) ?>"
                                                    <?= $a['role_name'] === $key
                                                        ? 'selected'
                                                        : '' ?>
                                                >
                                                    <?= escape($label) ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>

                                        <button
                                            type="submit"
                                            class="small-btn"
                                        >
                                            Save
                                        </button>
                                    </form>
                                <?php endif; ?>
                            </td>

                            <td>
                                <div class="user-actions">

                                    <?php if ($self): ?>
                                        <span class="user-note">
                                            Protected
                                        </span>

                                    <?php else: ?>
                                        <button
                                            type="button"
                                            class="small-btn <?= (int) $a['is_active'] ? 'danger' : '' ?>"
                                            data-id="<?= (int) $a['id'] ?>"
                                            data-name="<?= escape($a['full_name']) ?>"
                                            data-action="toggle_status"
                                            data-verb="<?= (int) $a['is_active'] ? 'deactivate' : 'activate' ?>"
                                            onclick="confirmUserAction(this)"
                                        >
                                            <?= (int) $a['is_active']
                                                ? 'Deactivate'
                                                : 'Activate' ?>
                                        </button>

                                        <button
                                            type="button"
                                            class="small-btn danger"
                                            data-id="<?= (int) $a['id'] ?>"
                                            data-name="<?= escape($a['full_name']) ?>"
                                            data-action="delete_user"
                                            data-verb="delete"
                                            onclick="confirmUserAction(this)"
                                        >
                                            Delete
                                        </button>
                                    <?php endif; ?>

                                </div>
                            </td>
                        </tr>

                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <p class="user-note">
                Delete disables account access and removes
                it from this list. Historical employee,
                applicant, and audit records are retained.
                Deleted emails cannot be re-registered
                automatically.
            </p>
        </section>

        <!-- AUDIT LOG -->
        <section class="dashboard-card users-panel">
            <h2>Recent Account Activity</h2>

            <?php if (!$events): ?>
                <p class="user-note">No activity yet.</p>

            <?php else: ?>
                <ul class="activity">
                    <?php foreach ($events as $e): ?>
                        <li>
                            <strong>
                                <?= escape($e['actor_name']) ?>
                            </strong>

                            —
                            <?= escape($e['action']) ?>

                            (
                            <?= escape(
                                $e['target_name'] ?? 'Unknown'
                            ) ?>
                            )

                            <div class="user-note">
                                <?= escape($e['details']) ?>
                                ·
                                <?= escape($e['created_at']) ?>
                            </div>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </section>

    </main>
</div>

<!-- ACCOUNT ACTION CONFIRMATION -->
<dialog class="confirm-dialog" id="accountDialog">

    <h3 id="accountTitle">Confirm Account Action</h3>

    <p id="accountMessage"></p>
    <p class="muted" id="accountNote"></p>

    <div class="dialog-actions">
        <button
            type="button"
            class="dialog-btn"
            onclick="document.getElementById('accountDialog').close()"
        >
            Cancel
        </button>

        <form action="users.php" method="POST">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape(csrf_token()) ?>"
            >

            <input
                type="hidden"
                name="action"
                id="accountAction"
            >

            <input
                type="hidden"
                name="user_id"
                id="accountUserId"
            >

            <button
                type="submit"
                class="dialog-btn confirm"
                id="accountConfirm"
            >
                Confirm
            </button>
        </form>
    </div>
</dialog>

<!-- LOGOUT CONFIRMATION -->
<dialog class="confirm-dialog" id="logoutDialog">

    <h3>Confirm Logout</h3>
    <p>Are you sure you want to log out?</p>

    <div class="dialog-actions">
        <form method="dialog">
            <button type="submit" class="dialog-btn">
                Cancel
            </button>
        </form>

        <form action="../logout.php" method="POST">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape(csrf_token()) ?>"
            >

            <button
                type="submit"
                class="dialog-btn confirm"
            >
                Log Out
            </button>
        </form>
    </div>
</dialog>

<script>
// COLLAPSIBLE SIDEBAR
document.getElementById('sidebarToggle')
    .addEventListener('click', () => {
        document.body.classList.toggle('collapsed');
    });

// LOGOUT
document.getElementById('openLogout')
    .addEventListener('click', () => {
        document.getElementById('logoutDialog')
            .showModal();
    });

// ACCOUNT CONFIRMATION
function confirmUserAction(button) {
    const verb = button.dataset.verb;

    document.getElementById('accountAction').value =
        button.dataset.action;

    document.getElementById('accountUserId').value =
        button.dataset.id;

    document.getElementById('accountTitle').textContent =
        verb === 'delete'
            ? 'Delete User Account'
            : 'Confirm Account Change';

    document.getElementById('accountMessage').textContent =
        'Are you sure you want to ' +
        verb + ' ' +
        button.dataset.name + '?';

    document.getElementById('accountNote').textContent =
        verb === 'delete'
            ? 'This removes the account from the active list and prevents login. Linked records and audit history stay saved.'
            : '';

    document.getElementById('accountConfirm').textContent =
        verb === 'delete'
            ? 'Delete Account'
            : 'Confirm';

    document.getElementById('accountDialog')
        .showModal();
}

// SEARCH ACCOUNTS
document.getElementById('userSearch')
    .addEventListener('input', function () {

        const q = this.value.trim().toLowerCase();

        document.querySelectorAll(
            '#usersTable tbody tr'
        ).forEach(row => {

            row.hidden =
                !row.textContent
                    .toLowerCase()
                    .includes(q);
        });
    });
</script>


<?php require __DIR__ . '/../includes/account_widget.php'; ?>
</body>

</html>
