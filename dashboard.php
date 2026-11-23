
<?php
require_once __DIR__ . '/includes/auth.php';

$user = require_login();

$role = $user['role_name'];

$roleLabel = ucwords(
    str_replace('_', ' ', $role)
);

$isHR = in_array(
    $role,
    ['administrator', 'hr_officer'],
    true
);

$canUseEmployeeTools =
    $isHR || $role === 'employee';

$application = null;

// APPLICANT APPLICATION STATUS
if ($role === 'applicant') {

    $stmt = $pdo->prepare(
        'SELECT
            position_applied,
            application_status,
            applied_at
         FROM job_applications
         WHERE user_id = ?
           AND deleted_at IS NULL
         ORDER BY applied_at DESC, id DESC
         LIMIT 1'
    );

    $stmt->execute([
        (int) $user['id']
    ]);

    $application = $stmt->fetch(
        PDO::FETCH_ASSOC
    );
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>
    Dashboard | McDonald's San Pedro Bayan
</title>

<link rel="stylesheet" href="css/style.css">

<style>
.dashboard-links {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin-top: 18px;
}

.dashboard-links .module-link {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 58px;
    padding: 16px;
    border: 1px solid #e3e9e1;
    border-radius: 12px;
    background: #f5f7f4;
    color: #526d57;
    text-decoration: none;
    font-size: 16px;
    font-weight: 600;
}

.dashboard-links .module-link:hover {
    background: #e8efe8;
}

.dashboard-links .module-icon {
    font-size: 22px;
    min-width: 24px;
    text-align: center;
}

.application-info p {
    margin: 12px 0;
    line-height: 1.6;
}
</style>
</head>

<body>

<div class="dashboard-layout">

    <!-- SIDEBAR -->
    <aside class="sidebar">

        <button
            class="toggle-btn"
            id="sidebarToggle"
            type="button"
            aria-label="Toggle sidebar"
        >
            ☰
        </button>

        <div class="sidebar-brand">
            HR &amp; Payroll
        </div>

        <!-- DASHBOARD -->
        <a
            href="dashboard.php"
            class="sidebar-item active"
        >
            <span class="sidebar-icon">⌂</span>

            <span class="sidebar-text">
                Dashboard
            </span>
        </a>

        <!-- HR / ADMIN -->
        <?php if ($isHR): ?>

            <a
                href="pages/employees.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">♙</span>

                <span class="sidebar-text">
                    Employees
                </span>
            </a>

            <a
                href="pages/recruitment.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">▤</span>

                <span class="sidebar-text">
                    Recruitment
                </span>
            </a>

        <?php endif; ?>

        <!-- ATTENDANCE / LEAVE / OVERTIME -->
        <?php if ($canUseEmployeeTools): ?>

            <a
                href="pages/attendance.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">◷</span>

                <span class="sidebar-text">
                    <?= $isHR
                        ? 'Attendance'
                        : 'My Attendance' ?>
                </span>
            </a>

            <a
                href="pages/leave.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">▦</span>

                <span class="sidebar-text">
                    <?= $isHR
                        ? 'Leave Management'
                        : 'My Leave' ?>
                </span>
            </a>

            <a
                href="pages/overtime.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">⏱</span>

                <span class="sidebar-text">
                    <?= $isHR
                        ? 'Overtime'
                        : 'My Overtime' ?>
                </span>
            </a>

        <?php endif; ?>

        <!-- ADMINISTRATOR ONLY -->
        <?php if ($role === 'administrator'): ?>

            <a
                href="pages/users.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">⚙</span>

                <span class="sidebar-text">
                    Users &amp; Roles
                </span>
            </a>

        <?php endif; ?>

        <!-- APPLICANT -->
        <?php if ($role === 'applicant'): ?>

            <a
                href="#application"
                class="sidebar-item"
            >
                <span class="sidebar-icon">▤</span>

                <span class="sidebar-text">
                    My Application
                </span>
            </a>

        <?php endif; ?>

        <!-- LOGOUT -->
        <button
            class="sidebar-item"
            id="openLogout"
            type="button"
        >
            <span class="sidebar-icon">⇥</span>

            <span class="sidebar-text">
                Log Out
            </span>
        </button>

    </aside>

    <!-- MAIN CONTENT -->
    <main class="dashboard-main">

        <header class="topbar">

            <div>
                <strong>
                    McDonald's San Pedro Bayan
                </strong>

                <div class="muted">
                    HR &amp; Payroll Management System
                </div>
            </div>

            <span class="role-tag">
                <?= escape($roleLabel) ?>
            </span>

        </header>

        <h1 class="dashboard-title">
            Welcome,
            <?= escape($user['full_name']) ?>!
        </h1>

        <section class="dashboard-card">

            <h3>
                <?= escape($roleLabel) ?> Dashboard
            </h3>

            <!-- APPLICANT DASHBOARD -->
            <?php if ($role === 'applicant'): ?>

                <p class="muted">
                    Track your online job
                    application below.
                </p>

                <div
                    id="application"
                    class="application-info"
                >

                    <h3>My Application</h3>

                    <?php if ($application): ?>

                        <p>
                            <strong>Position:</strong>

                            <?= escape(
                                $application['position_applied']
                            ) ?>
                        </p>

                        <p>
                            <strong>Status:</strong>

                            <?= escape(
                                ucwords(
                                    str_replace(
                                        '_',
                                        ' ',
                                        $application['application_status']
                                    )
                                )
                            ) ?>
                        </p>

                        <p>
                            <strong>Applied On:</strong>

                            <?= escape(
                                $application['applied_at']
                            ) ?>
                        </p>

                    <?php else: ?>

                        <p class="muted">
                            No active application found.
                        </p>

                    <?php endif; ?>

                </div>

            <!-- HR / ADMIN DASHBOARD -->
            <?php elseif ($isHR): ?>

                <p class="muted">
                    Manage employee records, recruitment,
                    attendance, leave and overtime requests.
                </p>

                <div class="dashboard-links">

                    <a
                        href="pages/employees.php"
                        class="module-link"
                    >
                        <span class="module-icon">♙</span>
                        Employee Management
                    </a>

                    <a
                        href="pages/recruitment.php"
                        class="module-link"
                    >
                        <span class="module-icon">▤</span>
                        Recruitment
                    </a>

                    <a
                        href="pages/attendance.php"
                        class="module-link"
                    >
                        <span class="module-icon">◷</span>
                        Attendance
                    </a>

                    <a
                        href="pages/leave.php"
                        class="module-link"
                    >
                        <span class="module-icon">▦</span>
                        Leave Management
                    </a>

                    <a
                        href="pages/overtime.php"
                        class="module-link"
                    >
                        <span class="module-icon">⏱</span>
                        Overtime Management
                    </a>

                    <?php if (
                        $role === 'administrator'
                    ): ?>

                        <a
                            href="pages/users.php"
                            class="module-link"
                        >
                            <span class="module-icon">⚙</span>
                            Users &amp; Roles
                        </a>

                    <?php endif; ?>

                </div>

            <!-- EMPLOYEE DASHBOARD -->
            <?php elseif ($role === 'employee'): ?>

                <p class="muted">
                    See your assigned shifts,
                    record Time In and Time Out,
                    submit leave requests and
                    request overtime.
                </p>

                <div class="dashboard-links">

                    <a
                        href="pages/attendance.php"
                        class="module-link"
                    >
                        <span class="module-icon">◷</span>
                        My Attendance
                    </a>

                    <a
                        href="pages/leave.php"
                        class="module-link"
                    >
                        <span class="module-icon">▦</span>
                        My Leave Requests
                    </a>

                    <a
                        href="pages/overtime.php"
                        class="module-link"
                    >
                        <span class="module-icon">⏱</span>
                        My Overtime
                    </a>

                </div>

            <!-- OTHER INTERNAL ROLES -->
            <?php else: ?>

                <p class="muted">
                    Your account is authenticated.
                    Authorized modules for this role
                    will be connected in later steps.
                </p>

            <?php endif; ?>

        </section>

    </main>

</div>

<!-- LOGOUT CONFIRMATION -->
<dialog
    class="confirm-dialog"
    id="logoutDialog"
>

    <h3>Confirm Logout</h3>

    <p>
        Are you sure you want to log out?
    </p>

    <div class="dialog-actions">

        <form method="dialog">

            <button
                class="dialog-btn"
                type="submit"
            >
                Cancel
            </button>

        </form>

        <form
            action="logout.php"
            method="POST"
        >

            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape(csrf_token()) ?>"
            >

            <button
                class="dialog-btn confirm"
                type="submit"
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

// LOGOUT CONFIRMATION
document.getElementById('openLogout')
    .addEventListener('click', () => {
        document.getElementById('logoutDialog')
            .showModal();
    });
</script>

<!-- ACCOUNT INFORMATION -->
<?php
require __DIR__ . '/includes/account_widget.php';
?>


<?php require __DIR__ . '/../includes/account_widget.php'; ?>
</body>

</html>
