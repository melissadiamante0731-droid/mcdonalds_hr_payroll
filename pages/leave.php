
<?php
require_once __DIR__ . '/../includes/auth.php';
date_default_timezone_set('Asia/Manila');

$user = current_user();
if (!$user) {
    header('Location: ../index.php');
    exit;
}

$role = $user['role_name'];
$isHR = in_array($role, ['administrator', 'hr_officer'], true);
$isEmployee = $role === 'employee';

if (!$isHR && !$isEmployee) {
    http_response_code(403);
    exit('Access denied.');
}

$leaveTypes = ['Vacation', 'Sick', 'Emergency', 'Personal', 'Other'];
$today = date('Y-m-d');

function leaveAudit(
    PDO $pdo,
    int $actor,
    ?int $target,
    string $action,
    int $id
): void {
    $stmt = $pdo->prepare(
        'INSERT INTO audit_logs
         (actor_user_id, target_user_id, action, details)
         VALUES (?, ?, ?, ?)'
    );
    $stmt->execute([
        $actor, $target, $action, 'Leave request #' . $id
    ]);
}

function checkedDate(string $text): DateTimeImmutable {
    $d = DateTimeImmutable::createFromFormat('!Y-m-d', $text);

    if (!$d || $d->format('Y-m-d') !== $text) {
        throw new RuntimeException('Invalid leave date.');
    }

    return $d;
}

function positiveId($value): int {
    $id = filter_var(
        $value,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1]]
    );

    if (!$id) {
        throw new RuntimeException('Invalid record ID.');
    }

    return (int) $id;
}

// PROCESS REQUESTS
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $message = 'Unable to process request.';
    $kind = 'error';

    try {
        if (!valid_csrf()) {
            throw new RuntimeException(
                'Invalid security token. Refresh the page.'
            );
        }

        $action = (string) ($_POST['action'] ?? '');
        $actor = (int) $user['id'];

        $pdo->beginTransaction();

        // EMPLOYEE SUBMITS LEAVE
        if ($action === 'request' && $isEmployee) {
            $type = (string) ($_POST['leave_type'] ?? '');
            $start = checkedDate(
                (string) ($_POST['start_date'] ?? '')
            );
            $end = checkedDate(
                (string) ($_POST['end_date'] ?? '')
            );
            $reason = trim(
                (string) ($_POST['reason'] ?? '')
            );

            if (!in_array($type, $leaveTypes, true)) {
                throw new RuntimeException(
                    'Choose a leave type.'
                );
            }

            if ($start > $end) {
                throw new RuntimeException(
                    'End date cannot be before start date.'
                );
            }

            if ($start->format('Y-m-d') < $today) {
                throw new RuntimeException(
                    'Choose today or a future date.'
                );
            }

            if ($start->diff($end)->days + 1 > 60) {
                throw new RuntimeException(
                    'Maximum is 60 calendar days per request in this prototype.'
                );
            }

            if (
                strlen($reason) < 10 ||
                strlen($reason) > 1000
            ) {
                throw new RuntimeException(
                    'Reason must be 10–1000 characters.'
                );
            }

            $stmt = $pdo->prepare(
                "SELECT id FROM employees
                 WHERE user_id = ?
                   AND employment_status = 'Active'
                   AND deleted_at IS NULL
                 FOR UPDATE"
            );

            $stmt->execute([$actor]);
            $employeeId = $stmt->fetchColumn();

            if (!$employeeId) {
                throw new RuntimeException(
                    'Your Employee login must be linked to an active employee record.'
                );
            }

            // PREVENT OVERLAPPING REQUESTS
            $stmt = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM leave_requests
                 WHERE employee_id = ?
                   AND deleted_at IS NULL
                   AND status IN ('Pending', 'Approved')
                   AND start_date <= ?
                   AND end_date >= ?"
            );

            $stmt->execute([
                $employeeId,
                $end->format('Y-m-d'),
                $start->format('Y-m-d')
            ]);

            if ((int) $stmt->fetchColumn() > 0) {
                throw new RuntimeException(
                    'You already have an overlapping pending/approved request.'
                );
            }

            $stmt = $pdo->prepare(
                'INSERT INTO leave_requests
                 (
                    employee_id,
                    leave_type,
                    start_date,
                    end_date,
                    reason
                 )
                 VALUES (?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $employeeId,
                $type,
                $start->format('Y-m-d'),
                $end->format('Y-m-d'),
                $reason
            ]);

            $requestId = (int) $pdo->lastInsertId();

            leaveAudit(
                $pdo,
                $actor,
                $actor,
                'LEAVE_REQUEST',
                $requestId
            );

            $message = 'Leave request submitted!';

        // EMPLOYEE CANCELS PENDING REQUEST
        } elseif ($action === 'cancel' && $isEmployee) {
            $id = positiveId($_POST['request_id'] ?? null);

            $stmt = $pdo->prepare(
                'SELECT lr.status
                 FROM leave_requests lr
                 JOIN employees e
                   ON e.id = lr.employee_id
                 WHERE lr.id = ?
                   AND e.user_id = ?
                   AND lr.deleted_at IS NULL
                 FOR UPDATE'
            );

            $stmt->execute([$id, $actor]);

            if ($stmt->fetchColumn() !== 'Pending') {
                throw new RuntimeException(
                    'Only your own pending request can be cancelled.'
                );
            }

            $stmt = $pdo->prepare(
                "UPDATE leave_requests
                 SET status = 'Cancelled'
                 WHERE id = ?"
            );

            $stmt->execute([$id]);

            leaveAudit(
                $pdo, $actor, $actor, 'LEAVE_CANCEL', $id
            );

            $message = 'Pending request cancelled.';

        // HR / ADMIN APPROVES OR REJECTS
        } elseif ($action === 'review' && $isHR) {
            $id = positiveId($_POST['request_id'] ?? null);

            $decision = (string) (
                $_POST['decision'] ?? ''
            );
            $paid = (string) (
                $_POST['is_paid'] ?? ''
            );
            $note = trim(
                (string) ($_POST['review_note'] ?? '')
            );

            if (!in_array(
                $decision,
                ['Approved', 'Rejected'],
                true
            )) {
                throw new RuntimeException(
                    'Invalid decision.'
                );
            }

            if (strlen($note) > 255) {
                throw new RuntimeException(
                    'Review note is too long.'
                );
            }

            if (
                $decision === 'Rejected' &&
                strlen($note) < 5
            ) {
                throw new RuntimeException(
                    'Please give a reason for rejection.'
                );
            }

            if (
                $decision === 'Approved' &&
                !in_array($paid, ['0', '1'], true)
            ) {
                throw new RuntimeException(
                    'Choose Paid or Unpaid.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT lr.*, e.user_id
                 FROM leave_requests lr
                 JOIN employees e
                   ON e.id = lr.employee_id
                 WHERE lr.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$id]);
            $r = $stmt->fetch(PDO::FETCH_ASSOC);

            if (
                !$r ||
                $r['deleted_at'] !== null ||
                $r['status'] !== 'Pending'
            ) {
                throw new RuntimeException(
                    'Only pending, non-archived leave can be reviewed.'
                );
            }

            if ($decision === 'Approved') {
                $stmt = $pdo->prepare(
                    "SELECT COUNT(*)
                     FROM leave_requests
                     WHERE employee_id = ?
                       AND id <> ?
                       AND deleted_at IS NULL
                       AND status = 'Approved'
                       AND start_date <= ?
                       AND end_date >= ?"
                );

                $stmt->execute([
                    $r['employee_id'],
                    $id,
                    $r['end_date'],
                    $r['start_date']
                ]);

                if ((int) $stmt->fetchColumn() > 0) {
                    throw new RuntimeException(
                        'An approved leave already covers these dates.'
                    );
                }
            }

            $stmt = $pdo->prepare(
                'UPDATE leave_requests
                 SET status = ?,
                     is_paid = ?,
                     review_note = ?,
                     reviewed_by = ?,
                     reviewed_at = NOW()
                 WHERE id = ?'
            );

            $stmt->execute([
                $decision,
                $decision === 'Approved'
                    ? (int) $paid : null,
                $note !== '' ? $note : null,
                $actor,
                $id
            ]);

            leaveAudit(
                $pdo,
                $actor,
                $r['user_id'] === null
                    ? null
                    : (int) $r['user_id'],
                'LEAVE_REVIEW',
                $id
            );

            $message =
                'Leave request ' . strtolower($decision) . '.';

        // HR / ADMIN ARCHIVES OR RESTORES
        } elseif (
            in_array($action, ['archive', 'restore'], true) &&
            $isHR
        ) {
            $id = positiveId($_POST['request_id'] ?? null);

            $stmt = $pdo->prepare(
                'SELECT lr.*, e.user_id
                 FROM leave_requests lr
                 JOIN employees e
                   ON e.id = lr.employee_id
                 WHERE lr.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$id]);
            $r = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$r) {
                throw new RuntimeException(
                    'Leave record not found.'
                );
            }

            if ($action === 'archive') {
                if ($r['deleted_at'] !== null) {
                    throw new RuntimeException(
                        'Already archived.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE leave_requests
                     SET deleted_at = NOW()
                     WHERE id = ?'
                );

                $log = 'LEAVE_ARCHIVE';

                $message =
                    'Leave request archived. Find it under Archived.';

            } else {
                if ($r['deleted_at'] === null) {
                    throw new RuntimeException(
                        'Record is not archived.'
                    );
                }

                if (in_array(
                    $r['status'],
                    ['Pending', 'Approved'],
                    true
                )) {
                    $check = $pdo->prepare(
                        "SELECT COUNT(*)
                         FROM leave_requests
                         WHERE employee_id = ?
                           AND id <> ?
                           AND deleted_at IS NULL
                           AND status IN ('Pending', 'Approved')
                           AND start_date <= ?
                           AND end_date >= ?"
                    );

                    $check->execute([
                        $r['employee_id'],
                        $id,
                        $r['end_date'],
                        $r['start_date']
                    ]);

                    if ((int) $check->fetchColumn() > 0) {
                        throw new RuntimeException(
                            'Cannot restore: dates overlap another active leave request.'
                        );
                    }
                }

                $stmt = $pdo->prepare(
                    'UPDATE leave_requests
                     SET deleted_at = NULL
                     WHERE id = ?'
                );

                $log = 'LEAVE_RESTORE';
                $message = 'Leave request restored.';
            }

            $stmt->execute([$id]);

            leaveAudit(
                $pdo,
                $actor,
                $r['user_id'] === null
                    ? null
                    : (int) $r['user_id'],
                $log,
                $id
            );

        } else {
            throw new RuntimeException(
                'Not authorized for this action.'
            );
        }

        $pdo->commit();
        $kind = 'success';

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
        $message =
            'Database error. Check the leave_requests table.';
    }

    $_SESSION['leave_flash'] = [$kind, $message];

    header('Location: leave.php', true, 303);
    exit;
}

// LOAD REQUESTS
$flash = $_SESSION['leave_flash'] ?? null;
unset($_SESSION['leave_flash']);

$sql = '
    SELECT
        lr.*,
        e.full_name,
        e.employee_code,
        d.department_name
    FROM leave_requests lr
    JOIN employees e
      ON e.id = lr.employee_id
    JOIN departments d
      ON d.id = e.department_id
';

if ($isHR) {
    $requests = $pdo->query(
        $sql .
        ' ORDER BY lr.created_at DESC, lr.id DESC
          LIMIT 300'
    )->fetchAll();
} else {
    $stmt = $pdo->prepare(
        $sql .
        ' WHERE e.user_id = ?
          ORDER BY lr.created_at DESC, lr.id DESC
          LIMIT 300'
    );

    $stmt->execute([(int) $user['id']]);
    $requests = $stmt->fetchAll();
}

$pending = 0;
$approved = 0;
$activeCount = 0;

foreach ($requests as $r) {
    if ($r['deleted_at'] !== null) {
        continue;
    }

    $activeCount++;

    if ($r['status'] === 'Pending') {
        $pending++;
    }

    if ($r['status'] === 'Approved') {
        $approved++;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Leave Management | McDonald's San Pedro Bayan</title>

<link rel="stylesheet" href="../css/style.css">

<style>
.leave-heading {
    margin: 28px 0 20px;
}

.leave-heading h1 {
    font-size: 32px;
    margin: 0 0 7px;
}

.leave-stats {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin: 20px 0;
}

.leave-stats strong {
    display: block;
    color: var(--green-dark);
    font-size: 31px;
    margin-top: 8px;
}

.leave-panel {
    margin: 20px 0;
}

.leave-panel h2 {
    font-size: 23px;
    margin: 0 0 14px;
}

.leave-form {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.leave-field label {
    display: block;
    font-weight: 600;
    margin: 0 0 8px;
}

.leave-field input,
.leave-field select,
.leave-field textarea,
.leave-search,
.leave-filter {
    width: 100%;
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: 9px;
    background: white;
    color: var(--text);
    font: inherit;
}

.leave-field textarea {
    resize: vertical;
    min-height: 90px;
}

.leave-wide {
    grid-column: 1 / -1;
}

.leave-btn {
    background: var(--green);
    color: white;
    border: 0;
    border-radius: 9px;
    padding: 11px 16px;
    font-weight: 700;
    cursor: pointer;
}

.leave-btn.secondary {
    background: var(--light-green);
    color: var(--green-dark);
}

.leave-btn.danger {
    background: #f9e7e7;
    color: #9b3434;
}

.leave-tools {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 14px 0;
}

.leave-search {
    flex: 2;
    min-width: 200px;
}

.leave-filter {
    flex: 1;
    min-width: 155px;
}

.leave-scroll {
    overflow: auto;
}

.leave-table {
    width: 100%;
    min-width: 870px;
    border-collapse: collapse;
}

.leave-table th,
.leave-table td {
    padding: 14px 10px;
    text-align: left;
    vertical-align: top;
    border-bottom: 1px solid var(--border);
    font-size: 15px;
}

.leave-table small {
    display: block;
    color: var(--muted);
    margin-top: 5px;
}

.leave-status {
    display: inline-block;
    border-radius: 20px;
    padding: 7px 11px;
    background: var(--light-green);
    color: var(--green-dark);
    font-weight: bold;
    font-size: 13px;
}

.leave-status.Pending {
    background: #f9f0d9;
    color: #795b20;
}

.leave-status.Rejected,
.leave-status.Cancelled,
.leave-status.Archived {
    background: #f9e7e7;
    color: #9b3434;
}

.leave-notice {
    padding: 14px;
    border-radius: 10px;
    margin: 16px 0;
}

.leave-notice.success {
    background: var(--light-green);
    color: var(--green-dark);
}

.leave-notice.error {
    background: #f9e7e7;
    color: #9b3434;
}

.leave-note {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
}

.leave-dialog {
    width: min(460px, 95vw);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 24px;
    color: var(--text);
}

.leave-dialog::backdrop {
    background: rgba(15, 25, 18, .5);
}

.leave-dialog h3 {
    margin: 0 0 14px;
}

.leave-dialog label {
    display: block;
    font-weight: 600;
    margin: 12px 0 8px;
}

.leave-dialog select,
.leave-dialog textarea {
    width: 100%;
    padding: 11px;
    border: 1px solid var(--border);
    border-radius: 9px;
    background: white;
}

.leave-dialog textarea {
    min-height: 80px;
}

.leave-actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 20px;
}

.leave-dots {
    width: 38px;
    height: 38px;
    border-radius: 9px;
    border: 1px solid var(--border);
    background: var(--light-green);
    font-size: 24px;
    cursor: pointer;
}

.leave-table tr[hidden] {
    display: none;
}

@media (max-width: 760px) {
    .leave-stats,
    .leave-form {
        grid-template-columns: 1fr;
    }

    .leave-wide {
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
    >☰</button>

    <div class="sidebar-brand">
        HR &amp; Payroll
    </div>

    <a class="sidebar-item" href="../dashboard.php">
        <span class="sidebar-icon">⌂</span>
        <span class="sidebar-text">Dashboard</span>
    </a>

    <?php if ($isHR): ?>

        <a class="sidebar-item" href="employees.php">
            <span class="sidebar-icon">♙</span>
            <span class="sidebar-text">Employees</span>
        </a>

        <a class="sidebar-item" href="recruitment.php">
            <span class="sidebar-icon">▤</span>
            <span class="sidebar-text">Recruitment</span>
        </a>

    <?php endif; ?>

    <a class="sidebar-item" href="attendance.php">
        <span class="sidebar-icon">◷</span>
        <span class="sidebar-text">
            <?= $isHR ? 'Attendance' : 'My Attendance' ?>
        </span>
    </a>

    <a class="sidebar-item active" href="leave.php">
        <span class="sidebar-icon">▦</span>
        <span class="sidebar-text">
            <?= $isHR ? 'Leave Management' : 'My Leave' ?>
        </span>
    </a>

    <?php if ($role === 'administrator'): ?>
        <a class="sidebar-item" href="users.php">
            <span class="sidebar-icon">⚙</span>
            <span class="sidebar-text">Users &amp; Roles</span>
        </a>
    <?php endif; ?>

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

    <span class="role-tag">
        <?= escape(
            ucwords(str_replace('_', ' ', $role))
        ) ?>
    </span>
</header>

<div class="leave-heading">
    <h1>
        <?= $isHR
            ? 'Leave Management'
            : 'My Leave Requests' ?>
    </h1>

    <p class="muted">
        <?= $isHR
            ? 'Approve or reject employee leave requests.'
            : 'Submit leave requests and track their status.' ?>
    </p>
</div>

<?php if ($flash): ?>
    <div class="leave-notice <?= escape($flash[0]) ?>">
        <?= escape($flash[1]) ?>
    </div>
<?php endif; ?>

<div class="leave-stats">
    <div class="dashboard-card">
        <span class="muted">Requests</span>
        <strong><?= $activeCount ?></strong>
    </div>

    <div class="dashboard-card">
        <span class="muted">Pending</span>
        <strong><?= $pending ?></strong>
    </div>

    <div class="dashboard-card">
        <span class="muted">Approved</span>
        <strong><?= $approved ?></strong>
    </div>
</div>

<?php if ($isEmployee): ?>

<section class="dashboard-card leave-panel">
    <h2>Request Leave</h2>

    <form
        method="POST"
        action="leave.php"
        class="leave-form"
    >
        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input
            type="hidden"
            name="action"
            value="request"
        >

        <div class="leave-field">
            <label for="leaveType">Leave Type</label>

            <select
                id="leaveType"
                name="leave_type"
                required
            >
                <option value="">Select Leave Type</option>

                <?php foreach ($leaveTypes as $type): ?>
                    <option value="<?= escape($type) ?>">
                        <?= escape($type) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="leave-field">
            <label for="leaveStart">Start Date</label>

            <input
                id="leaveStart"
                name="start_date"
                type="date"
                min="<?= $today ?>"
                required
            >
        </div>

        <div class="leave-field">
            <label for="leaveEnd">End Date</label>

            <input
                id="leaveEnd"
                name="end_date"
                type="date"
                min="<?= $today ?>"
                required
            >
        </div>

        <div class="leave-field leave-wide">
            <label for="leaveReason">Reason</label>

            <textarea
                id="leaveReason"
                name="reason"
                minlength="10"
                maxlength="1000"
                required
            ></textarea>
        </div>

        <div class="leave-wide">
            <button class="leave-btn" type="submit">
                Submit Leave Request
            </button>
        </div>
    </form>

    <p class="leave-note">
        Requests for today or later, up to 60 calendar
        days. Paid or Unpaid is decided by HR/Admin.
    </p>
</section>

<?php endif; ?>

<section class="dashboard-card leave-panel">

    <h2>
        <?= $isHR
            ? 'All Leave Requests'
            : 'My Leave History' ?>
    </h2>

    <div class="leave-tools">

        <input
            class="leave-search"
            type="search"
            id="leaveSearch"
            placeholder="Search employee or leave type..."
        >

        <select class="leave-filter" id="leaveFilter">
            <option value="">All Statuses</option>
            <option>Pending</option>
            <option>Approved</option>
            <option>Rejected</option>
            <option>Cancelled</option>
            <option>Archived</option>
        </select>

    </div>

    <div class="leave-scroll">
        <table class="leave-table" id="leaveTable">

            <thead>
                <tr>
                    <?php if ($isHR): ?>
                        <th>Employee</th>
                    <?php endif; ?>

                    <th>Type</th>
                    <th>Dates</th>
                    <th>Reason</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>

            <tbody>

            <?php foreach ($requests as $r): ?>
                <?php
                $archived =
                    $r['deleted_at'] !== null;
                ?>

                <tr
                    data-status="<?= escape($r['status']) ?>"
                    data-archived="<?= $archived ? '1' : '0' ?>"
                >

                    <?php if ($isHR): ?>
                        <td>
                            <strong>
                                <?= escape($r['full_name']) ?>
                            </strong>

                            <small>
                                <?= escape(
                                    $r['employee_code'] .
                                    ' · ' .
                                    $r['department_name']
                                ) ?>
                            </small>
                        </td>
                    <?php endif; ?>

                    <td>
                        <?= escape($r['leave_type']) ?>

                        <small>
                            Filed
                            <?= escape(
                                date(
                                    'M d, Y',
                                    strtotime($r['created_at'])
                                )
                            ) ?>
                        </small>
                    </td>

                    <td>
                        <?= escape($r['start_date']) ?>

                        <small>
                            to
                            <?= escape($r['end_date']) ?>
                        </small>
                    </td>

                    <td>
                        <?= nl2br(escape($r['reason'])) ?>
                    </td>

                    <td>
                        <span class="leave-status <?= $archived
                            ? 'Archived'
                            : escape($r['status']) ?>"
                        >
                            <?= $archived
                                ? 'Archived'
                                : escape($r['status']) ?>
                        </span>

                        <?php if (
                            $r['status'] === 'Approved'
                        ): ?>
                            <small>
                                <?= (int) $r['is_paid'] === 1
                                    ? 'Paid'
                                    : 'Unpaid' ?>
                                Leave
                            </small>
                        <?php endif; ?>

                        <?php if ($r['review_note']): ?>
                            <small>
                                HR note:
                                <?= escape($r['review_note']) ?>
                            </small>
                        <?php endif; ?>
                    </td>

                    <td>
                        <?php if (
                            $isHR &&
                            !$archived &&
                            $r['status'] === 'Pending'
                        ): ?>

                            <button
                                type="button"
                                class="leave-btn"
                                data-id="<?= (int) $r['id'] ?>"
                                data-name="<?= escape(
                                    $r['full_name']
                                ) ?>"
                                data-decision="Approved"
                                onclick="openReview(this)"
                            >
                                Approve
                            </button>

                            <button
                                type="button"
                                class="leave-btn danger"
                                data-id="<?= (int) $r['id'] ?>"
                                data-name="<?= escape(
                                    $r['full_name']
                                ) ?>"
                                data-decision="Rejected"
                                onclick="openReview(this)"
                            >
                                Reject
                            </button>

                        <?php elseif (
                            $isEmployee &&
                            !$archived &&
                            $r['status'] === 'Pending'
                        ): ?>

                            <button
                                type="button"
                                class="leave-btn secondary"
                                data-id="<?= (int) $r['id'] ?>"
                                onclick="openCancel(this)"
                            >
                                Cancel
                            </button>

                        <?php endif; ?>

                        <?php if ($isHR): ?>
                            <button
                                type="button"
                                class="leave-dots"
                                aria-label="Leave actions"
                                data-id="<?= (int) $r['id'] ?>"
                                data-archived="<?= $archived
                                    ? '1'
                                    : '0' ?>"
                                onclick="openArchive(this)"
                            >
                                ⋮
                            </button>
                        <?php endif; ?>
                    </td>

                </tr>
            <?php endforeach; ?>

            </tbody>

        </table>
    </div>

    <p class="leave-note">
        Approved leave is not yet part of salary
        calculation. Archive does not permanently erase
        records; Restore is under Archived.
    </p>
</section>

</main>
</div>

<?php if ($isHR): ?>

<!-- REVIEW POPUP -->
<dialog class="leave-dialog" id="reviewDialog">

    <h3>Review Leave Request</h3>
    <p id="reviewTitle"></p>

    <form method="POST" action="leave.php">

        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input type="hidden" name="action" value="review">
        <input type="hidden" name="request_id" id="reviewId">
        <input type="hidden" name="decision" id="reviewDecision">

        <div id="paidGroup">
            <label for="paidOption">Paid or Unpaid</label>

            <select id="paidOption" name="is_paid">
                <option value="">Select classification</option>
                <option value="1">Paid</option>
                <option value="0">Unpaid</option>
            </select>
        </div>

        <label for="reviewNote">HR Note</label>
        <textarea
            id="reviewNote"
            name="review_note"
            maxlength="255"
        ></textarea>

        <div class="leave-actions">
            <button
                type="button"
                class="dialog-btn"
                onclick="reviewDialog.close()"
            >
                Cancel
            </button>

            <button
                type="submit"
                class="leave-btn"
                id="reviewSubmit"
            >
                Confirm
            </button>
        </div>

    </form>
</dialog>

<!-- THREE-DOT ACTION POPUP -->
<dialog class="leave-dialog" id="archiveDialog">

    <h3>Leave Record Actions</h3>
    <p id="archiveMessage"></p>

    <div class="leave-actions">
        <button
            class="dialog-btn"
            type="button"
            onclick="archiveDialog.close()"
        >
            Cancel
        </button>

        <button
            class="leave-btn danger"
            id="openArchiveConfirm"
            type="button"
        >
            Delete
        </button>
    </div>
</dialog>

<!-- DELETE / RESTORE CONFIRMATION -->
<dialog class="leave-dialog" id="archiveConfirmDialog">

    <h3 id="archiveTitle">Confirm Delete</h3>
    <p id="archiveConfirmMessage"></p>

    <form method="POST" action="leave.php">

        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input
            type="hidden"
            name="request_id"
            id="archiveId"
        >

        <input
            type="hidden"
            name="action"
            id="archiveAction"
        >

        <div class="leave-actions">

            <button
                class="dialog-btn"
                type="button"
                onclick="archiveConfirmDialog.close()"
            >
                Cancel
            </button>

            <button
                class="leave-btn danger"
                type="submit"
                id="archiveSubmit"
            >
                Yes, Delete
            </button>

        </div>
    </form>
</dialog>

<?php endif; ?>

<?php if ($isEmployee): ?>

<!-- EMPLOYEE CANCEL POPUP -->
<dialog class="leave-dialog" id="cancelDialog">

    <h3>Cancel Leave Request?</h3>
    <p>This will cancel your pending request.</p>

    <form method="POST" action="leave.php">

        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input type="hidden" name="action" value="cancel">
        <input type="hidden" name="request_id" id="cancelId">

        <div class="leave-actions">

            <button
                class="dialog-btn"
                type="button"
                onclick="cancelDialog.close()"
            >
                Back
            </button>

            <button
                class="leave-btn danger"
                type="submit"
            >
                Yes, Cancel
            </button>

        </div>
    </form>
</dialog>

<?php endif; ?>

<!-- LOGOUT POPUP -->
<dialog class="confirm-dialog" id="logoutDialog">

    <h3>Confirm Logout</h3>
    <p>Are you sure you want to log out?</p>

    <div class="dialog-actions">
        <form method="dialog">
            <button class="dialog-btn">Cancel</button>
        </form>

        <form action="../logout.php" method="POST">

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
// SIDEBAR AND LOGOUT
document.getElementById('sidebarToggle')
    .addEventListener('click', () => {
        document.body.classList.toggle('collapsed');
    });

document.getElementById('openLogout')
    .addEventListener('click', () => {
        document.getElementById('logoutDialog')
            .showModal();
    });

// FILTER LEAVE RECORDS
function filterLeaves() {
    const q = document.getElementById('leaveSearch')
        .value.toLowerCase().trim();

    const status = document.getElementById('leaveFilter')
        .value;

    document.querySelectorAll(
        '#leaveTable tbody tr[data-status]'
    ).forEach(row => {

        const archived =
            row.dataset.archived === '1';

        const matches = status === 'Archived'
            ? archived
            : !archived && (
                !status ||
                row.dataset.status === status
            );

        row.hidden =
            !matches ||
            !row.textContent.toLowerCase().includes(q);
    });
}

document.getElementById('leaveSearch')
    .addEventListener('input', filterLeaves);

document.getElementById('leaveFilter')
    .addEventListener('change', filterLeaves);

filterLeaves();

<?php if ($isHR): ?>

// APPROVE OR REJECT
const reviewDialog =
    document.getElementById('reviewDialog');

function openReview(button) {
    const approve =
        button.dataset.decision === 'Approved';

    document.getElementById('reviewId').value =
        button.dataset.id;

    document.getElementById('reviewDecision').value =
        button.dataset.decision;

    document.getElementById('reviewTitle').textContent =
        (approve ? 'Approve' : 'Reject') +
        ' request for ' +
        button.dataset.name + '?';

    document.getElementById('paidGroup').hidden =
        !approve;

    document.getElementById('paidOption').required =
        approve;

    document.getElementById('paidOption').value = '';

    document.getElementById('reviewNote').required =
        !approve;

    document.getElementById('reviewNote').value = '';

    document.getElementById('reviewSubmit').textContent =
        approve ? 'Approve' : 'Reject';

    reviewDialog.showModal();
}

// DELETE OR RESTORE
const archiveDialog =
    document.getElementById('archiveDialog');

const archiveConfirmDialog =
    document.getElementById('archiveConfirmDialog');

let selectedArchive = null;

function openArchive(button) {
    selectedArchive = {
        id: button.dataset.id,
        archived: button.dataset.archived === '1'
    };

    document.getElementById('archiveMessage').textContent =
        'Leave request #' + selectedArchive.id;

    document.getElementById('openArchiveConfirm').textContent =
        selectedArchive.archived ? 'Restore' : 'Delete';

    archiveDialog.showModal();
}

document.getElementById('openArchiveConfirm')
    .addEventListener('click', () => {

        if (!selectedArchive) return;

        document.getElementById('archiveId').value =
            selectedArchive.id;

        document.getElementById('archiveAction').value =
            selectedArchive.archived
                ? 'restore'
                : 'archive';

        document.getElementById('archiveTitle').textContent =
            selectedArchive.archived
                ? 'Restore Record?'
                : 'Delete Record?';

        document.getElementById(
            'archiveConfirmMessage'
        ).textContent =
            (selectedArchive.archived
                ? 'Restore'
                : 'Archive') +
            ' leave request #' +
            selectedArchive.id + '?';

        document.getElementById('archiveSubmit').textContent =
            selectedArchive.archived
                ? 'Yes, Restore'
                : 'Yes, Delete';

        archiveDialog.close();
        archiveConfirmDialog.showModal();
    });

<?php endif; ?>

<?php if ($isEmployee): ?>

// CANCEL OWN LEAVE REQUEST
const cancelDialog =
    document.getElementById('cancelDialog');

function openCancel(button) {
    document.getElementById('cancelId').value =
        button.dataset.id;

    cancelDialog.showModal();
}

// LEAVE DATE VALIDATION
const startDate =
    document.getElementById('leaveStart');

const endDate =
    document.getElementById('leaveEnd');

startDate.addEventListener('change', () => {
    endDate.min =
        startDate.value || '<?= $today ?>';

    if (
        endDate.value &&
        endDate.value < startDate.value
    ) {
        endDate.value = '';
    }
});

<?php endif; ?>
</script>


<?php require __DIR__ . '/../includes/account_widget.php'; ?>
</body>

</html>
