
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

$statuses = [
    'submitted' => 'Submitted',
    'under_review' => 'Under Review',
    'for_interview' => 'For Interview',
    'hired' => 'Hired',
    'rejected' => 'Rejected'
];

function recruitment_audit(
    PDO $pdo,
    int $actor,
    ?int $target,
    string $action,
    string $details
): void {
    $stmt = $pdo->prepare(
        'INSERT INTO audit_logs
         (actor_user_id, target_user_id, action, details)
         VALUES (?, ?, ?, ?)'
    );
    $stmt->execute([
        $actor, $target, $action, $details
    ]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $type = 'error';
    $message = 'Action failed.';

    try {
        if (!valid_csrf()) {
            throw new RuntimeException(
                'Invalid request. Refresh the page.'
            );
        }

        $action = (string) ($_POST['action'] ?? '');
        $actor = (int) $user['id'];

        $pdo->beginTransaction();

        // OPEN OR REOPEN A HIRING POSITION
        if ($action === 'open_position') {
            $positionId = filter_var(
                $_POST['position_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$positionId) {
                throw new RuntimeException(
                    'Select a valid position.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT p.id
                 FROM positions p
                 JOIN departments d
                   ON d.id = p.department_id
                 WHERE p.id = ?
                   AND d.is_active = 1'
            );
            $stmt->execute([$positionId]);

            if (!$stmt->fetchColumn()) {
                throw new RuntimeException(
                    'Position is not in an active department.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT id, is_open, deleted_at
                 FROM job_openings
                 WHERE position_id = ?
                 FOR UPDATE'
            );
            $stmt->execute([$positionId]);
            $existing = $stmt->fetch();

            if (
                $existing &&
                (int) $existing['is_open'] === 1 &&
                $existing['deleted_at'] === null
            ) {
                throw new RuntimeException(
                    'This position is already open.'
                );
            }

            if ($existing) {
                $stmt = $pdo->prepare(
                    'UPDATE job_openings
                     SET is_open = 1,
                         opened_at = NOW(),
                         closed_at = NULL,
                         deleted_at = NULL
                     WHERE id = ?'
                );
                $stmt->execute([(int) $existing['id']]);
                $openingId = (int) $existing['id'];
            } else {
                $stmt = $pdo->prepare(
                    'INSERT INTO job_openings
                     (position_id, created_by)
                     VALUES (?, ?)'
                );
                $stmt->execute([
                    $positionId, $actor
                ]);
                $openingId = (int) $pdo->lastInsertId();
            }

            recruitment_audit(
                $pdo,
                $actor,
                null,
                'OPEN_POSITION',
                'Opened hiring position #' . $openingId
            );

            $message = 'Position opened successfully.';

        // CLOSE / REOPEN HIRING
        } elseif ($action === 'toggle_opening') {
            $openingId = filter_var(
                $_POST['opening_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$openingId) {
                throw new RuntimeException(
                    'Invalid hiring position.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT
                    o.is_open,
                    o.deleted_at,
                    d.is_active
                 FROM job_openings o
                 JOIN positions p
                   ON p.id = o.position_id
                 JOIN departments d
                   ON d.id = p.department_id
                 WHERE o.id = ?
                 FOR UPDATE'
            );
            $stmt->execute([$openingId]);
            $opening = $stmt->fetch();

            if (
                !$opening ||
                $opening['deleted_at'] !== null
            ) {
                throw new RuntimeException(
                    'Position not found or archived.'
                );
            }

            if ((int) $opening['is_open'] === 1) {
                $stmt = $pdo->prepare(
                    'UPDATE job_openings
                     SET is_open = 0,
                         closed_at = NOW()
                     WHERE id = ?'
                );
                $stmt->execute([$openingId]);

                $message = 'Hiring closed.';
                $logAction = 'CLOSE_POSITION';
            } else {
                if ((int) $opening['is_active'] !== 1) {
                    throw new RuntimeException(
                        'Department is inactive.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE job_openings
                     SET is_open = 1,
                         opened_at = NOW(),
                         closed_at = NULL
                     WHERE id = ?'
                );
                $stmt->execute([$openingId]);

                $message = 'Hiring reopened.';
                $logAction = 'REOPEN_POSITION';
            }

            recruitment_audit(
                $pdo,
                $actor,
                null,
                $logAction,
                'Hiring position #' . $openingId
            );

        // UPDATE APPLICATION STATUS
        } elseif ($action === 'update_application') {
            $applicationId = filter_var(
                $_POST['application_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            $status = (string) (
                $_POST['application_status'] ?? ''
            );

            if (
                !$applicationId ||
                !isset($statuses[$status])
            ) {
                throw new RuntimeException(
                    'Invalid application or status.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT user_id,
                        application_status,
                        deleted_at
                 FROM job_applications
                 WHERE id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$applicationId]);
            $application = $stmt->fetch();

            if (
                !$application ||
                $application['deleted_at'] !== null
            ) {
                throw new RuntimeException(
                    'Application not found or archived.'
                );
            }

            if (
                $application['application_status'] ===
                $status
            ) {
                throw new RuntimeException(
                    'Application already has that status.'
                );
            }

            $stmt = $pdo->prepare(
                'UPDATE job_applications
                 SET application_status = ?
                 WHERE id = ?'
            );
            $stmt->execute([
                $status, $applicationId
            ]);

            recruitment_audit(
                $pdo,
                $actor,
                (int) $application['user_id'],
                'APPLICATION_STATUS',
                'Application #' . $applicationId .
                ': ' . $application['application_status'] .
                ' → ' . $status
            );

            $message = 'Application status updated.';

        // DELETE OR RESTORE HIRING POSITION
        } elseif (
            $action === 'archive_opening' ||
            $action === 'restore_opening'
        ) {
            $openingId = filter_var(
                $_POST['opening_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$openingId) {
                throw new RuntimeException('Invalid position.');
            }

            $stmt = $pdo->prepare(
                'SELECT deleted_at
                 FROM job_openings
                 WHERE id = ?
                 FOR UPDATE'
            );
            $stmt->execute([$openingId]);
            $opening = $stmt->fetch();

            if (!$opening) {
                throw new RuntimeException(
                    'Hiring position not found.'
                );
            }

            if ($action === 'archive_opening') {
                if ($opening['deleted_at'] !== null) {
                    throw new RuntimeException(
                        'Position already archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE job_openings
                     SET deleted_at = NOW(),
                         is_open = 0,
                         closed_at = NOW()
                     WHERE id = ?'
                );
                $stmt->execute([$openingId]);

                $message = 'Hiring position deleted from list.';
                $auditAction = 'ARCHIVE_OPENING';
            } else {
                if ($opening['deleted_at'] === null) {
                    throw new RuntimeException(
                        'Position is not archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE job_openings
                     SET deleted_at = NULL,
                         is_open = 0
                     WHERE id = ?'
                );
                $stmt->execute([$openingId]);

                $message = 'Position restored as Closed.';
                $auditAction = 'RESTORE_OPENING';
            }

            recruitment_audit(
                $pdo, $actor, null, $auditAction,
                'Hiring position #' . $openingId
            );

        // DELETE OR RESTORE APPLICATION
        } elseif (
            $action === 'archive_application' ||
            $action === 'restore_application'
        ) {
            $applicationId = filter_var(
                $_POST['application_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$applicationId) {
                throw new RuntimeException(
                    'Invalid application.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT user_id, deleted_at
                 FROM job_applications
                 WHERE id = ?
                 FOR UPDATE'
            );
            $stmt->execute([$applicationId]);
            $application = $stmt->fetch();

            if (!$application) {
                throw new RuntimeException(
                    'Application not found.'
                );
            }

            if ($action === 'archive_application') {
                if ($application['deleted_at'] !== null) {
                    throw new RuntimeException(
                        'Application already archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE job_applications
                     SET deleted_at = NOW()
                     WHERE id = ?'
                );
                $stmt->execute([$applicationId]);

                $message = 'Application deleted from active list.';
                $auditAction = 'ARCHIVE_APPLICATION';
            } else {
                if ($application['deleted_at'] === null) {
                    throw new RuntimeException(
                        'Application is not archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE job_applications
                     SET deleted_at = NULL
                     WHERE id = ?'
                );
                $stmt->execute([$applicationId]);

                $message = 'Application restored.';
                $auditAction = 'RESTORE_APPLICATION';
            }

            recruitment_audit(
                $pdo,
                $actor,
                (int) $application['user_id'],
                $auditAction,
                'Application #' . $applicationId
            );
        } else {
            throw new RuntimeException('Unknown action.');
        }

        $pdo->commit();
        $type = 'success';

    } catch (RuntimeException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $message = $e->getMessage();

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log($e->getMessage());
        $message = 'Unable to save. Check database setup.';
    }

    $_SESSION['recruitment_flash'] = [
        'type' => $type,
        'message' => $message
    ];

    header('Location: recruitment.php', true, 303);
    exit;
}

$flash = $_SESSION['recruitment_flash'] ?? null;
unset($_SESSION['recruitment_flash']);

$departments = $pdo->query(
    'SELECT id, department_name
     FROM departments
     WHERE is_active = 1
     ORDER BY department_name'
)->fetchAll();

$positions = $pdo->query(
    'SELECT p.id, p.department_id, p.position_name
     FROM positions p
     JOIN departments d ON d.id = p.department_id
     WHERE d.is_active = 1
     ORDER BY p.position_name'
)->fetchAll();

$openings = $pdo->query(
    'SELECT
        o.id,
        o.is_open,
        o.deleted_at,
        p.position_name,
        d.department_name,
        (
            SELECT COUNT(*)
            FROM job_applications a
            WHERE a.job_opening_id = o.id
              AND a.deleted_at IS NULL
        ) AS applicant_count
     FROM job_openings o
     JOIN positions p ON p.id = o.position_id
     JOIN departments d ON d.id = p.department_id
     ORDER BY o.is_open DESC,
              d.department_name,
              p.position_name'
)->fetchAll();

$applications = $pdo->query(
    'SELECT
        a.id,
        a.application_status,
        a.deleted_at,
        a.applied_at,
        u.full_name,
        u.email,
        COALESCE(
            p.position_name,
            a.position_applied
        ) AS job_title,
        d.department_name
     FROM job_applications a
     JOIN users u ON u.id = a.user_id
     LEFT JOIN job_openings o
       ON o.id = a.job_opening_id
     LEFT JOIN positions p
       ON p.id = o.position_id
     LEFT JOIN departments d
       ON d.id = p.department_id
     ORDER BY a.applied_at DESC,
              a.id DESC'
)->fetchAll();

$openCount = 0;
$pendingCount = 0;
$applicationCount = 0;

foreach ($openings as $o) {
    if (
        $o['deleted_at'] === null &&
        (int) $o['is_open'] === 1
    ) {
        $openCount++;
    }
}

foreach ($applications as $a) {
    if ($a['deleted_at'] !== null) {
        continue;
    }

    $applicationCount++;

    if (in_array(
        $a['application_status'],
        ['submitted', 'under_review', 'for_interview'],
        true
    )) {
        $pendingCount++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1">
<title>Recruitment | McDonald's San Pedro Bayan</title>
<link rel="stylesheet" href="../css/style.css">

<style>
.page-heading {
    margin: 26px 0;
}

.page-heading h1 {
    font-size: 32px;
    margin: 0 0 8px;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin: 20px 0;
}

.summary-grid strong {
    display: block;
    color: var(--green-dark);
    font-size: 30px;
    margin-top: 8px;
}

.panel {
    margin-bottom: 20px;
}

.panel h2 {
    font-size: 22px;
    margin-top: 0;
}

.hiring-form {
    display: grid;
    grid-template-columns: 1fr 1fr auto;
    gap: 14px;
    align-items: end;
}

.form-field label {
    display: block;
    font-weight: 600;
    margin-bottom: 8px;
}

.form-field select,
.filter-bar input,
.filter-bar select,
.status-form select {
    width: 100%;
    min-height: 45px;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: 9px;
    background: white;
    color: var(--text);
}

.action-btn {
    min-height: 45px;
    background: var(--green);
    color: white;
    padding: 11px 16px;
    border: 0;
    border-radius: 9px;
    font-weight: bold;
    cursor: pointer;
}

.small-btn {
    background: var(--light-green);
    color: var(--green-dark);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 9px 12px;
    cursor: pointer;
}

.small-btn.danger,
.danger-action {
    background: #f9e7e7;
    color: #a23f3f;
}

.table-scroll {
    overflow-x: auto;
}

table {
    width: 100%;
    min-width: 780px;
    border-collapse: collapse;
}

th, td {
    text-align: left;
    padding: 13px 10px;
    border-bottom: 1px solid var(--border);
    font-size: 15px;
    vertical-align: middle;
}

th {
    color: var(--muted);
}

td small {
    display: block;
    color: var(--muted);
    margin-top: 4px;
}

.status-form {
    display: flex;
    gap: 8px;
    align-items: center;
}

.status-form select {
    min-width: 150px;
}

.pill {
    display: inline-block;
    border-radius: 25px;
    background: var(--light-green);
    color: var(--green-dark);
    padding: 7px 11px;
    font-size: 13px;
    font-weight: bold;
}

.pill.closed {
    background: #f9e7e7;
    color: #a23f3f;
}

.pill.archived {
    background: #f1ebdd;
    color: #755c30;
}

.filter-bar {
    display: flex;
    gap: 12px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}

.filter-bar input {
    flex: 2;
    min-width: 180px;
}

.filter-bar select {
    flex: 1;
    min-width: 160px;
}

.notice {
    padding: 13px 16px;
    border-radius: 10px;
    margin: 16px 0;
}

.notice.success {
    background: var(--light-green);
    color: var(--green-dark);
}

.notice.error {
    background: #f9e7e7;
    color: #a23f3f;
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

.dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 20px;
    flex-wrap: wrap;
}

tr[hidden] {
    display: none;
}

@media (max-width: 800px) {
    .summary-grid,
    .hiring-form {
        grid-template-columns: 1fr;
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

    <a href="employees.php" class="sidebar-item">
        <span class="sidebar-icon">♙</span>
        <span class="sidebar-text">Employees</span>
    </a>

    <a href="recruitment.php"
       class="sidebar-item active">
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

<div class="page-heading">
    <h1>Recruitment Management</h1>
    <p class="muted">
        Manage hiring positions and review applications.
    </p>
</div>

<?php if ($flash): ?>
    <div class="notice <?= escape($flash['type']) ?>">
        <?= escape($flash['message']) ?>
    </div>
<?php endif; ?>

<div class="summary-grid">
    <div class="dashboard-card">
        <span class="muted">Open Positions</span>
        <strong><?= $openCount ?></strong>
    </div>

    <div class="dashboard-card">
        <span class="muted">Applications</span>
        <strong><?= $applicationCount ?></strong>
    </div>

    <div class="dashboard-card">
        <span class="muted">
            Pending Review / Interview
        </span>
        <strong><?= $pendingCount ?></strong>
    </div>
</div>

<!-- OPEN HIRING POSITION -->
<section class="dashboard-card panel">
    <h2>Open a Hiring Position</h2>

    <p class="muted">
        Only open positions appear on Applicant Sign Up.
    </p>

    <form method="POST"
          action="recruitment.php"
          class="hiring-form">

        <input type="hidden" name="csrf_token"
               value="<?= escape(csrf_token()) ?>">

        <input type="hidden" name="action"
               value="open_position">

        <div class="form-field">
            <label for="department">Department</label>
            <select id="department" required>
                <option value="">Select Department</option>

                <?php foreach ($departments as $d): ?>
                    <option value="<?= (int) $d['id'] ?>">
                        <?= escape($d['department_name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="form-field">
            <label for="position">Position</label>
            <select id="position"
                    name="position_id"
                    required disabled>
                <option value="">
                    Select Department First
                </option>

                <?php foreach ($positions as $p): ?>
                    <option
                        value="<?= (int) $p['id'] ?>"
                        data-dept="<?= (int) $p['department_id'] ?>">
                        <?= escape($p['position_name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <button class="action-btn" type="submit">
            Open Hiring
        </button>
    </form>
</section>

<!-- HIRING POSITIONS -->
<section class="dashboard-card panel">
    <h2>Hiring Positions</h2>

    <div class="filter-bar">
        <select id="openingFilter"
                aria-label="Filter hiring positions">
            <option value="">All Positions</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
            <option value="archived">Archived</option>
        </select>
    </div>

    <div class="table-scroll">
        <table id="openingTable">
            <thead>
                <tr>
                    <th>Department</th>
                    <th>Position</th>
                    <th>Applications</th>
                    <th>Status</th>
                    <th>Hiring</th>
                    <th>⋮</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($openings as $o): ?>
                <?php
                $archived = $o['deleted_at'] !== null;
                $openingState = $archived
                    ? 'archived'
                    : ((int) $o['is_open'] ? 'open' : 'closed');
                ?>

                <tr data-opening-state="<?= $openingState ?>">
                    <td>
                        <?= escape($o['department_name']) ?>
                    </td>

                    <td>
                        <?= escape($o['position_name']) ?>
                    </td>

                    <td>
                        <?= (int) $o['applicant_count'] ?>
                    </td>

                    <td>
                        <span class="pill <?= $archived
                            ? 'archived'
                            : ((int) $o['is_open'] ? '' : 'closed') ?>">
                            <?= $archived
                                ? 'Archived'
                                : ((int) $o['is_open']
                                    ? 'Open'
                                    : 'Closed') ?>
                        </span>
                    </td>

                    <td>
                        <?php if (!$archived): ?>
                            <button
                                class="small-btn"
                                type="button"
                                data-id="<?= (int) $o['id'] ?>"
                                data-title="<?= escape(
                                    $o['position_name']
                                ) ?>"
                                data-verb="<?= (int) $o['is_open']
                                    ? 'close'
                                    : 'reopen' ?>"
                                onclick="confirmOpening(this)">
                                <?= (int) $o['is_open']
                                    ? 'Close Hiring'
                                    : 'Reopen' ?>
                            </button>
                        <?php else: ?>
                            <span class="muted">Restore first</span>
                        <?php endif; ?>
                    </td>

                    <td>
                        <button
                            type="button"
                            class="dots-btn"
                            aria-label="Position actions"
                            data-type="opening"
                            data-id="<?= (int) $o['id'] ?>"
                            data-label="<?= escape(
                                $o['position_name']
                            ) ?>"
                            data-archived="<?= $archived
                                ? '1'
                                : '0' ?>"
                            onclick="openRecordActions(this)">
                            ⋮
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <p class="muted" id="openingEmpty" hidden>
        No positions match this filter.
    </p>
</section>

<!-- ONLINE APPLICATIONS -->
<section class="dashboard-card panel">
    <h2>Online Applications</h2>

    <div class="filter-bar">
        <input
            id="applicationSearch"
            type="search"
            placeholder="Search name, email or position..."
            aria-label="Search applications">

        <select id="applicationFilter"
                aria-label="Application statuses">
            <option value="">All Statuses</option>

            <?php foreach ($statuses as $key => $label): ?>
                <option value="<?= escape($key) ?>">
                    <?= escape($label) ?>
                </option>
            <?php endforeach; ?>

            <option value="archived">Archived</option>
        </select>
    </div>

    <div class="table-scroll">
        <table id="applicationTable">
            <thead>
                <tr>
                    <th>Applicant</th>
                    <th>Applied For</th>
                    <th>Date</th>
                    <th>Status / Update</th>
                    <th>⋮</th>
                </tr>
            </thead>

            <tbody>
            <?php foreach ($applications as $a): ?>
                <?php $archived = $a['deleted_at'] !== null; ?>

                <tr
                    data-status="<?= escape(
                        $a['application_status']
                    ) ?>"
                    data-archived="<?= $archived ? '1' : '0' ?>">

                    <td>
                        <strong>
                            <?= escape($a['full_name']) ?>
                        </strong>
                        <small>
                            <?= escape($a['email']) ?>
                        </small>
                    </td>

                    <td>
                        <?= escape($a['job_title']) ?>
                        <small>
                            <?= escape(
                                $a['department_name'] ??
                                'Previous application'
                            ) ?>
                        </small>
                    </td>

                    <td><?= escape($a['applied_at']) ?></td>

                    <td>
                        <?php if ($archived): ?>
                            <span class="pill archived">
                                Archived —
                                <?= escape(
                                    $statuses[
                                        $a['application_status']
                                    ] ?? $a['application_status']
                                ) ?>
                            </span>
                        <?php else: ?>
                            <form
                                method="POST"
                                action="recruitment.php"
                                class="status-form">

                                <input
                                    type="hidden"
                                    name="csrf_token"
                                    value="<?= escape(
                                        csrf_token()
                                    ) ?>">

                                <input
                                    type="hidden"
                                    name="action"
                                    value="update_application">

                                <input
                                    type="hidden"
                                    name="application_id"
                                    value="<?= (int) $a['id'] ?>">

                                <select name="application_status"
                                        aria-label="Update status">
                                    <?php foreach (
                                        $statuses as $key => $label
                                    ): ?>
                                        <option
                                            value="<?= escape($key) ?>"
                                            <?= $a['application_status']
                                                === $key
                                                ? 'selected'
                                                : '' ?>>
                                            <?= escape($label) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>

                                <button class="small-btn"
                                        type="submit">
                                    Save
                                </button>
                            </form>
                        <?php endif; ?>
                    </td>

                    <td>
                        <button
                            type="button"
                            class="dots-btn"
                            aria-label="Application actions"
                            data-type="application"
                            data-id="<?= (int) $a['id'] ?>"
                            data-label="<?= escape(
                                $a['full_name'] .
                                ' — ' .
                                $a['job_title']
                            ) ?>"
                            data-archived="<?= $archived
                                ? '1'
                                : '0' ?>"
                            onclick="openRecordActions(this)">
                            ⋮
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <p class="muted" id="applicationEmpty" hidden>
        No applications match this filter.
    </p>

    <p class="muted">
        Hired status records a hiring decision only.
        Employee records and login access are managed
        separately.
    </p>
</section>

</main>
</div>

<!-- CONFIRM OPEN/CLOSE HIRING -->
<dialog class="confirm-dialog" id="openingDialog">
    <h3>Confirm Hiring Change</h3>
    <p id="openingMessage"></p>

    <div class="dialog-actions">
        <button class="dialog-btn" type="button"
                onclick="openingDialog.close()">
            Cancel
        </button>

        <form action="recruitment.php" method="POST">
            <input type="hidden" name="csrf_token"
                   value="<?= escape(csrf_token()) ?>">
            <input type="hidden" name="action"
                   value="toggle_opening">
            <input type="hidden" name="opening_id"
                   id="openingId">

            <button class="dialog-btn confirm"
                    type="submit">
                Confirm
            </button>
        </form>
    </div>
</dialog>

<!-- THREE-DOT MENU -->
<dialog class="confirm-dialog" id="recordActionsDialog">
    <h3>Record Actions</h3>
    <p id="recordActionsLabel"></p>
    <p class="muted" id="recordActionsNote"></p>

    <div class="dialog-actions">
        <button class="dialog-btn" type="button"
                onclick="recordActionsDialog.close()">
            Cancel
        </button>

        <button class="dialog-btn danger-action"
                type="button" id="recordActionButton">
            Delete
        </button>
    </div>
</dialog>

<!-- DELETE / RESTORE CONFIRMATION -->
<dialog class="confirm-dialog" id="recordConfirmDialog">
    <h3 id="recordConfirmTitle">
        Confirm Record Action
    </h3>

    <p id="recordConfirmMessage"></p>

    <div class="dialog-actions">
        <button class="dialog-btn" type="button"
                onclick="recordConfirmDialog.close()">
            Cancel
        </button>

        <form action="recruitment.php" method="POST">
            <input type="hidden" name="csrf_token"
                   value="<?= escape(csrf_token()) ?>">
            <input type="hidden" name="action"
                   id="recordAction">
            <input type="hidden" name="opening_id"
                   id="recordOpeningId">
            <input type="hidden" name="application_id"
                   id="recordApplicationId">

            <button class="dialog-btn confirm"
                    type="submit" id="recordSubmit">
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
        <button class="dialog-btn" type="button"
                onclick="logoutDialog.close()">
            Cancel
        </button>

        <form action="../logout.php" method="POST">
            <input type="hidden" name="csrf_token"
                   value="<?= escape(csrf_token()) ?>">

            <button class="dialog-btn confirm"
                    type="submit">
                Log Out
            </button>
        </form>
    </div>
</dialog>

<script>
const department = document.getElementById('department');
const position = document.getElementById('position');

const positionList = Array.from(position.options)
    .filter(option => option.value)
    .map(option => ({
        id: option.value,
        name: option.textContent,
        department: option.dataset.dept
    }));

department.addEventListener('change', () => {
    position.replaceChildren();

    const blank = new Option(
        department.value
            ? 'Select Position'
            : 'Select Department First',
        ''
    );
    position.add(blank);

    const matches = positionList.filter(
        item => item.department === department.value
    );

    matches.forEach(item => {
        position.add(new Option(item.name, item.id));
    });

    position.disabled = matches.length === 0;
});

const openingDialog =
    document.getElementById('openingDialog');

const recordActionsDialog =
    document.getElementById('recordActionsDialog');

const recordConfirmDialog =
    document.getElementById('recordConfirmDialog');

const logoutDialog =
    document.getElementById('logoutDialog');

function confirmOpening(button) {
    document.getElementById('openingId').value =
        button.dataset.id;

    document.getElementById('openingMessage').textContent =
        'Are you sure you want to ' +
        button.dataset.verb + ' hiring for ' +
        button.dataset.title + '?';

    openingDialog.showModal();
}

let selectedRecord = null;

function openRecordActions(button) {
    selectedRecord = {
        type: button.dataset.type,
        id: button.dataset.id,
        label: button.dataset.label,
        archived: button.dataset.archived === '1'
    };

    document.getElementById(
        'recordActionsLabel'
    ).textContent = selectedRecord.label;

    document.getElementById(
        'recordActionsNote'
    ).textContent = selectedRecord.archived
        ? 'Restore this archived record.'
        : 'Delete will archive the record, not permanently erase it.';

    document.getElementById(
        'recordActionButton'
    ).textContent = selectedRecord.archived
        ? 'Restore'
        : 'Delete';

    recordActionsDialog.showModal();
}

document.getElementById('recordActionButton')
    .addEventListener('click', () => {
        if (!selectedRecord) return;

        document.getElementById(
            'recordAction'
        ).value =
            (selectedRecord.archived
                ? 'restore_'
                : 'archive_') + selectedRecord.type;

        document.getElementById(
            'recordOpeningId'
        ).value = selectedRecord.type === 'opening'
            ? selectedRecord.id
            : '';

        document.getElementById(
            'recordApplicationId'
        ).value = selectedRecord.type === 'application'
            ? selectedRecord.id
            : '';

        document.getElementById(
            'recordConfirmTitle'
        ).textContent = selectedRecord.archived
            ? 'Restore Record?'
            : 'Delete Record?';

        document.getElementById(
            'recordConfirmMessage'
        ).textContent =
            (selectedRecord.archived
                ? 'Restore '
                : 'Archive ') +
            selectedRecord.label + '?';

        document.getElementById(
            'recordSubmit'
        ).textContent = selectedRecord.archived
            ? 'Yes, Restore'
            : 'Yes, Delete';

        recordActionsDialog.close();
        recordConfirmDialog.showModal();
    });

function filterOpenings() {
    const status =
        document.getElementById('openingFilter').value;
    let visible = 0;

    document.querySelectorAll(
        '#openingTable tbody tr[data-opening-state]'
    ).forEach(row => {
        const archived =
            row.dataset.openingState === 'archived';

        const show = status === 'archived'
            ? archived
            : !archived && (
                !status ||
                row.dataset.openingState === status
            );

        row.hidden = !show;
        if (show) visible++;
    });

    document.getElementById('openingEmpty').hidden =
        visible > 0;
}

function filterApplications() {
    const search = document.getElementById(
        'applicationSearch'
    ).value.toLowerCase().trim();

    const status = document.getElementById(
        'applicationFilter'
    ).value;

    let visible = 0;

    document.querySelectorAll(
        '#applicationTable tbody tr[data-status]'
    ).forEach(row => {
        const archived =
            row.dataset.archived === '1';

        const statusMatches = status === 'archived'
            ? archived
            : !archived && (
                !status ||
                row.dataset.status === status
            );

        const show =
            statusMatches &&
            row.textContent.toLowerCase().includes(search);

        row.hidden = !show;

        if (show) visible++;
    });

    document.getElementById(
        'applicationEmpty'
    ).hidden = visible > 0;
}

document.getElementById('openingFilter')
    .addEventListener('change', filterOpenings);

document.getElementById('applicationSearch')
    .addEventListener('input', filterApplications);

document.getElementById('applicationFilter')
    .addEventListener('change', filterApplications);

filterOpenings();
filterApplications();

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
