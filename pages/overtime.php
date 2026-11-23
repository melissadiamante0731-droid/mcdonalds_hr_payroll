
<?php
require_once __DIR__ . '/../includes/auth.php';
date_default_timezone_set('Asia/Manila');

$user = require_login();
$role = (string) $user['role_name'];

$isHR = in_array(
    $role,
    ['administrator', 'hr_officer'],
    true
);

$isEmployee = $role === 'employee';

if (!$isHR && !$isEmployee) {
    http_response_code(403);
    exit('403 Forbidden: Overtime access denied.');
}

// =====================================
// HELPERS
// =====================================

function otPositiveId($value): int
{
    $result = filter_var(
        $value,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1]]
    );

    if ($result === false || $result === null) {
        throw new RuntimeException(
            'Invalid overtime request.'
        );
    }

    return (int) $result;
}

function otDate(string $value): string
{
    $date = DateTimeImmutable::createFromFormat(
        '!Y-m-d',
        $value
    );

    if (
        !$date ||
        $date->format('Y-m-d') !== $value
    ) {
        throw new RuntimeException(
            'Please select a valid overtime date.'
        );
    }

    return $value;
}

function otDuration(int $minutes): string
{
    $hours = intdiv($minutes, 60);
    $rest = $minutes % 60;

    if ($hours === 0) {
        return $minutes . ' minutes';
    }

    return $hours . ' hour'
        . ($hours === 1 ? '' : 's')
        . (
            $rest
                ? ' ' . $rest . ' minutes'
                : ''
        );
}

function otActualMinutes(array $row): ?int
{
    if (
        empty($row['time_in']) ||
        empty($row['time_out']) ||
        empty($row['ends_at'])
    ) {
        return null;
    }

    $start = strtotime($row['time_in']);
    $out = strtotime($row['time_out']);
    $end = strtotime($row['ends_at']);

    if (
        $start === false ||
        $out === false ||
        $end === false ||
        $out <= $start
    ) {
        return null;
    }

    return max(
        0,
        (int) floor(
            ($out - max($start, $end)) / 60
        )
    );
}

function otAudit(
    PDO $pdo,
    int $actor,
    ?int $target,
    string $action,
    string $details
): void {
    $statement = $pdo->prepare(
        'INSERT INTO audit_logs
         (
             actor_user_id,
             target_user_id,
             action,
             details
         )
         VALUES (?, ?, ?, ?)'
    );

    $statement->execute([
        $actor,
        $target,
        $action,
        $details
    ]);
}

// =====================================
// HANDLE FORM SUBMISSIONS
// =====================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $noticeType = 'error';
    $notice = 'Unable to process your request.';

    try {

        if (!valid_csrf()) {
            throw new RuntimeException(
                'Invalid security token. Refresh this page and try again.'
            );
        }

        $action = (string) (
            $_POST['action'] ?? ''
        );

        $actorId = (int) $user['id'];

        $pdo->beginTransaction();

        // =====================================
        // EMPLOYEE: REQUEST OVERTIME
        // =====================================

        if (
            $action === 'request' &&
            $isEmployee
        ) {

            $requestedDate = otDate(
                trim(
                    (string) (
                        $_POST['requested_date'] ?? ''
                    )
                )
            );

            $minutesInput = filter_var(
                $_POST['requested_minutes'] ?? null,
                FILTER_VALIDATE_INT
            );

            if (
                $minutesInput === false ||
                $minutesInput === null
            ) {
                throw new RuntimeException(
                    'Select an overtime duration.'
                );
            }

            $minutes = (int) $minutesInput;

            if (
                $minutes < 15 ||
                $minutes > 240 ||
                $minutes % 15 !== 0
            ) {
                throw new RuntimeException(
                    'Choose a duration from 15 minutes to 4 hours.'
                );
            }

            // FIND ACTIVE EMPLOYEE PROFILE

            $stmt = $pdo->prepare(
                "SELECT id, full_name
                 FROM employees
                 WHERE user_id = ?
                   AND employment_status = 'Active'
                   AND deleted_at IS NULL
                 LIMIT 1
                 FOR UPDATE"
            );

            $stmt->execute([$actorId]);

            $employee = $stmt->fetch(
                PDO::FETCH_ASSOC
            );

            if (!$employee) {
                throw new RuntimeException(
                    'No active employee profile is linked to this login. Ask HR to link your account.'
                );
            }

            $employeeId = (int) $employee['id'];

            // SHIFT IS OPTIONAL AT REQUEST TIME

            $stmt = $pdo->prepare(
                'SELECT id
                 FROM employee_shifts
                 WHERE employee_id = ?
                   AND shift_date = ?
                 LIMIT 1'
            );

            $stmt->execute([
                $employeeId,
                $requestedDate
            ]);

            $shiftId = $stmt->fetchColumn();

            $shiftId = $shiftId === false
                ? null
                : (int) $shiftId;

            // CHECK EXISTING REQUEST FOR DATE

            $stmt = $pdo->prepare(
                'SELECT
                    id,
                    status,
                    deleted_at
                 FROM overtime_requests
                 WHERE employee_id = ?
                   AND requested_date = ?
                 FOR UPDATE'
            );

            $stmt->execute([
                $employeeId,
                $requestedDate
            ]);

            $old = $stmt->fetch(
                PDO::FETCH_ASSOC
            );

            if ($old) {

                if ($old['deleted_at'] !== null) {
                    throw new RuntimeException(
                        'This date has an archived request. Ask HR/Admin to restore it.'
                    );
                }

                if (
                    !in_array(
                        $old['status'],
                        ['Rejected', 'Cancelled'],
                        true
                    )
                ) {
                    throw new RuntimeException(
                        'You already have a Pending or Approved request for this date.'
                    );
                }

                // RESUBMIT REQUEST

                $stmt = $pdo->prepare(
                    "UPDATE overtime_requests
                     SET
                         shift_id = ?,
                         requested_minutes = ?,
                         reason = '',
                         status = 'Pending',
                         reviewed_by = NULL,
                         reviewed_at = NULL,
                         review_note = NULL
                     WHERE id = ?"
                );

                $stmt->execute([
                    $shiftId,
                    $minutes,
                    (int) $old['id']
                ]);

                $requestId = (int) $old['id'];

                $auditAction = 'OVERTIME_RESUBMIT';

                $notice =
                    'Overtime request resubmitted for HR review.';

            } else {

                // NEW REQUEST
                // NO REASON FIELD REQUIRED

                $stmt = $pdo->prepare(
                    "INSERT INTO overtime_requests
                     (
                         shift_id,
                         employee_id,
                         requested_date,
                         requested_minutes,
                         reason,
                         status
                     )
                     VALUES
                     (?, ?, ?, ?, '', 'Pending')"
                );

                $stmt->execute([
                    $shiftId,
                    $employeeId,
                    $requestedDate,
                    $minutes
                ]);

                $requestId = (int) $pdo->lastInsertId();

                $auditAction = 'OVERTIME_REQUEST';

                $notice =
                    'Overtime request submitted for HR review.';
            }

            otAudit(
                $pdo,
                $actorId,
                $actorId,
                $auditAction,
                'Request #' . $requestId .
                ' | ' . $requestedDate .
                ' | ' . $minutes . ' minutes'
            );

        // =====================================
        // EMPLOYEE: CANCEL
        // =====================================

        } elseif (
            $action === 'cancel' &&
            $isEmployee
        ) {

            $requestId = otPositiveId(
                $_POST['request_id'] ?? null
            );

            $stmt = $pdo->prepare(
                'SELECT o.status
                 FROM overtime_requests o
                 JOIN employees e
                     ON e.id = o.employee_id
                 WHERE o.id = ?
                   AND e.user_id = ?
                   AND o.deleted_at IS NULL
                 FOR UPDATE'
            );

            $stmt->execute([
                $requestId,
                $actorId
            ]);

            if (
                $stmt->fetchColumn() !== 'Pending'
            ) {
                throw new RuntimeException(
                    'Only your Pending requests can be cancelled.'
                );
            }

            $pdo->prepare(
                "UPDATE overtime_requests
                 SET status = 'Cancelled'
                 WHERE id = ?"
            )->execute([$requestId]);

            otAudit(
                $pdo,
                $actorId,
                $actorId,
                'OVERTIME_CANCEL',
                'Request #' . $requestId
            );

            $notice = 'Overtime request cancelled.';

        // =====================================
        // HR / ADMIN: APPROVE OR REJECT
        // =====================================

        } elseif (
            $action === 'review' &&
            $isHR
        ) {

            $requestId = otPositiveId(
                $_POST['request_id'] ?? null
            );

            $decision = (string) (
                $_POST['decision'] ?? ''
            );

            $note = trim(
                (string) (
                    $_POST['review_note'] ?? ''
                )
            );

            if (
                !in_array(
                    $decision,
                    ['Approved', 'Rejected'],
                    true
                )
            ) {
                throw new RuntimeException(
                    'Select Approve or Reject.'
                );
            }

            if (
                strlen($note) > 255 ||
                (
                    $decision === 'Rejected' &&
                    strlen($note) < 5
                )
            ) {
                throw new RuntimeException(
                    'A rejection note must contain 5–255 characters.'
                );
            }

            $stmt = $pdo->prepare(
                'SELECT
                    o.status,
                    o.deleted_at,
                    o.requested_date,
                    o.requested_minutes,
                    e.user_id
                 FROM overtime_requests o
                 JOIN employees e
                     ON e.id = o.employee_id
                 WHERE o.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$requestId]);

            $item = $stmt->fetch(
                PDO::FETCH_ASSOC
            );

            if (
                !$item ||
                $item['deleted_at'] !== null ||
                $item['status'] !== 'Pending'
            ) {
                throw new RuntimeException(
                    'Only active Pending requests may be reviewed.'
                );
            }

            $stmt = $pdo->prepare(
                'UPDATE overtime_requests
                 SET
                     status = ?,
                     reviewed_by = ?,
                     reviewed_at = NOW(),
                     review_note = ?
                 WHERE id = ?'
            );

            $stmt->execute([
                $decision,
                $actorId,
                $note !== '' ? $note : null,
                $requestId
            ]);

            otAudit(
                $pdo,
                $actorId,
                $item['user_id'] === null
                    ? null
                    : (int) $item['user_id'],
                'OVERTIME_REVIEW',
                'Request #' . $requestId .
                ' | ' . $decision
            );

            $notice =
                'Overtime request ' .
                strtolower($decision) . '.';

        // =====================================
        // HR / ADMIN: ARCHIVE / RESTORE
        // =====================================

        } elseif (
            in_array(
                $action,
                ['archive', 'restore'],
                true
            ) &&
            $isHR
        ) {

            $requestId = otPositiveId(
                $_POST['request_id'] ?? null
            );

            $stmt = $pdo->prepare(
                'SELECT
                    o.deleted_at,
                    e.user_id
                 FROM overtime_requests o
                 JOIN employees e
                     ON e.id = o.employee_id
                 WHERE o.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$requestId]);

            $item = $stmt->fetch(
                PDO::FETCH_ASSOC
            );

            if (!$item) {
                throw new RuntimeException(
                    'Overtime request not found.'
                );
            }

            if ($action === 'archive') {

                if ($item['deleted_at'] !== null) {
                    throw new RuntimeException(
                        'This request is already archived.'
                    );
                }

                $pdo->prepare(
                    'UPDATE overtime_requests
                     SET deleted_at = NOW()
                     WHERE id = ?'
                )->execute([$requestId]);

                $auditAction = 'OVERTIME_ARCHIVE';

                $notice = 'Overtime request archived.';

            } else {

                if ($item['deleted_at'] === null) {
                    throw new RuntimeException(
                        'This request is not archived.'
                    );
                }

                $pdo->prepare(
                    'UPDATE overtime_requests
                     SET deleted_at = NULL
                     WHERE id = ?'
                )->execute([$requestId]);

                $auditAction = 'OVERTIME_RESTORE';

                $notice = 'Overtime request restored.';
            }

            otAudit(
                $pdo,
                $actorId,
                $item['user_id'] === null
                    ? null
                    : (int) $item['user_id'],
                $auditAction,
                'Request #' . $requestId
            );

        } else {

            throw new RuntimeException(
                'You are not authorized to perform this action.'
            );
        }

        $pdo->commit();

        $noticeType = 'success';

    } catch (RuntimeException $e) {

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        $notice = $e->getMessage();

    } catch (PDOException $e) {

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log(
            'Overtime DB: ' . $e->getMessage()
        );

        $notice = $e->getCode() === '23000'
            ? 'An overtime request already exists for this date.'
            : 'Database error. Run the overtime date migration first.';

    } catch (Throwable $e) {

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log(
            'Overtime: ' . $e->getMessage()
        );

        $notice =
            'Unexpected error. Please try again.';
    }

    $_SESSION['overtime_flash'] = [
        $noticeType,
        $notice
    ];

    header(
        'Location: overtime.php',
        true,
        303
    );

    exit;
}

// =====================================
// FLASH MESSAGE
// =====================================

$flash = $_SESSION['overtime_flash'] ?? null;

unset($_SESSION['overtime_flash']);

// =====================================
// EMPLOYEE PROFILE
// =====================================

$employeeProfile = null;

if ($isEmployee) {

    $stmt = $pdo->prepare(
        "SELECT
            id,
            employee_code,
            employment_status
         FROM employees
         WHERE user_id = ?
           AND deleted_at IS NULL
         LIMIT 1"
    );

    $stmt->execute([
        (int) $user['id']
    ]);

    $employeeProfile = $stmt->fetch(
        PDO::FETCH_ASSOC
    ) ?: null;
}

// =====================================
// LOAD OVERTIME REQUESTS
// =====================================

$baseSql =
    'SELECT
        o.*,
        e.full_name,
        e.employee_code,
        d.department_name,
        s.starts_at,
        s.ends_at,
        a.time_in,
        a.time_out
     FROM overtime_requests o
     JOIN employees e
         ON e.id = o.employee_id
     LEFT JOIN departments d
         ON d.id = e.department_id
     LEFT JOIN employee_shifts s
         ON s.employee_id = o.employee_id
        AND s.shift_date = o.requested_date
     LEFT JOIN attendance_records a
         ON a.shift_id = s.id';

if ($isHR) {

    $requests = $pdo->query(
        $baseSql .
        ' ORDER BY
            o.created_at DESC,
            o.id DESC
          LIMIT 300'
    )->fetchAll(PDO::FETCH_ASSOC);

} else {

    $stmt = $pdo->prepare(
        $baseSql .
        ' WHERE e.user_id = ?
            AND o.deleted_at IS NULL
          ORDER BY
            o.created_at DESC,
            o.id DESC
          LIMIT 300'
    );

    $stmt->execute([
        (int) $user['id']
    ]);

    $requests = $stmt->fetchAll(
        PDO::FETCH_ASSOC
    );
}

// =====================================
// DASHBOARD COUNTS
// =====================================

$counts = [
    'total' => 0,
    'pending' => 0,
    'approved' => 0
];

foreach ($requests as $request) {

    if ($request['deleted_at'] !== null) {
        continue;
    }

    $counts['total']++;

    if ($request['status'] === 'Pending') {
        $counts['pending']++;
    }

    if ($request['status'] === 'Approved') {
        $counts['approved']++;
    }
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
    Overtime | McDonald's San Pedro Bayan
</title>

<link
    rel="stylesheet"
    href="../css/style.css"
>

<style>
:root {
    --sage: #718b75;
    --sage-dark: #526d57;
    --line: #e3e9e1;
    --muted: #788078;
    --danger: #a03d3d;
}

.ot-title {
    margin: 26px 0 20px;
}

.ot-title h1 {
    margin: 0 0 8px;
    font-size: 32px;
}

.ot-stats {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin-bottom: 20px;
}

.ot-stat strong {
    display: block;
    font-size: 30px;
    margin-top: 9px;
    color: var(--sage-dark);
}

.ot-panel {
    margin-bottom: 20px;
}

.ot-panel h2 {
    margin: 0 0 13px;
    font-size: 23px;
}

.ot-intro {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.7;
}

.ot-form {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 15px;
    margin-top: 17px;
}

.ot-field label {
    display: block;
    font-weight: 700;
    margin-bottom: 8px;
}

.ot-field input,
.ot-field select,
.ot-tools input,
.ot-tools select,
.ot-dialog textarea {
    width: 100%;
    min-height: 45px;
    padding: 11px;
    border: 1px solid var(--line);
    border-radius: 9px;
    background: white;
    color: #26332a;
    font: inherit;
}

.ot-form-footer {
    grid-column: 1 / -1;
}

.ot-btn {
    display: inline-block;
    padding: 11px 16px;
    border: 0;
    border-radius: 9px;
    font: inherit;
    font-weight: 700;
    background: var(--sage);
    color: white;
    cursor: pointer;
}

.ot-btn:hover {
    background: var(--sage-dark);
}

.ot-btn.alt {
    background: #e8efe8;
    color: var(--sage-dark);
}

.ot-btn.danger {
    background: #f9e7e7;
    color: var(--danger);
}

.ot-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.ot-msg {
    margin: 0 0 18px;
    padding: 14px;
    border-radius: 10px;
}

.ot-msg.success {
    background: #e8efe8;
    color: var(--sage-dark);
}

.ot-msg.error {
    background: #f9e7e7;
    color: var(--danger);
}

.ot-tools {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 16px 0;
}

.ot-tools input {
    flex: 2;
    min-width: 190px;
}

.ot-tools select {
    flex: 1;
    min-width: 150px;
}

.ot-scroll {
    overflow-x: auto;
}

.ot-table {
    width: 100%;
    min-width: 820px;
    border-collapse: collapse;
}

.ot-table th,
.ot-table td {
    padding: 13px 10px;
    text-align: left;
    vertical-align: top;
    border-bottom: 1px solid var(--line);
    font-size: 14px;
}

.ot-table th {
    color: var(--muted);
}

.ot-table small {
    display: block;
    margin-top: 4px;
    color: var(--muted);
    line-height: 1.4;
}

.ot-tag {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 20px;
    background: #e8efe8;
    color: var(--sage-dark);
    font-size: 12px;
    font-weight: 700;
}

.ot-tag.Pending {
    background: #fbf0d5;
    color: #765b1f;
}

.ot-tag.Rejected,
.ot-tag.Cancelled,
.ot-tag.Archived {
    background: #f9e7e7;
    color: var(--danger);
}

.ot-actions {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
}

.ot-actions .ot-btn {
    font-size: 13px;
    padding: 8px 10px;
}

.ot-dots {
    width: 36px;
    height: 36px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: #e8efe8;
    color: var(--sage-dark);
    font-size: 22px;
    cursor: pointer;
}

.ot-dialog {
    width: min(470px, 94vw);
    max-height: 85vh;
    overflow: auto;
    padding: 24px;
    border: 1px solid var(--line);
    border-radius: 16px;
    color: #26332a;
    background: #fff;
}

.ot-dialog::backdrop {
    background: rgba(20, 32, 24, 0.55);
}

.ot-dialog h3 {
    margin: 0 0 10px;
}

.ot-dialog textarea {
    min-height: 90px;
    resize: vertical;
}

.ot-dialog label {
    display: block;
    font-weight: 700;
    margin: 13px 0 7px;
}

.ot-dialog-actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 9px;
    margin-top: 20px;
}

.ot-table tr[hidden] {
    display: none;
}

@media (max-width: 700px) {

    .ot-stats,
    .ot-form {
        grid-template-columns: 1fr;
    }

    .ot-title h1 {
        font-size: 27px;
    }
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

        <a
            href="../dashboard.php"
            class="sidebar-item"
        >
            <span class="sidebar-icon">⌂</span>
            <span class="sidebar-text">
                Dashboard
            </span>
        </a>

        <?php if ($isHR): ?>

            <a
                href="employees.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">♙</span>
                <span class="sidebar-text">
                    Employees
                </span>
            </a>

            <a
                href="recruitment.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">▤</span>
                <span class="sidebar-text">
                    Recruitment
                </span>
            </a>

        <?php endif; ?>

        <a
            href="attendance.php"
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
            href="leave.php"
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
            href="overtime.php"
            class="sidebar-item active"
        >
            <span class="sidebar-icon">⏱</span>
            <span class="sidebar-text">
                <?= $isHR
                    ? 'Overtime'
                    : 'My Overtime' ?>
            </span>
        </a>

        <?php if ($role === 'administrator'): ?>

            <a
                href="users.php"
                class="sidebar-item"
            >
                <span class="sidebar-icon">⚙</span>
                <span class="sidebar-text">
                    Users &amp; Roles
                </span>
            </a>

        <?php endif; ?>

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
                <?= escape(
                    ucwords(
                        str_replace('_', ' ', $role)
                    )
                ) ?>
            </span>

        </header>

        <div class="ot-title">

            <h1>
                <?= $isHR
                    ? 'Overtime Management'
                    : 'My Overtime' ?>
            </h1>

            <p class="muted">
                <?= $isHR
                    ? 'Review overtime requests in real time.'
                    : 'Choose a date and duration to request overtime, even before your shift is completed.' ?>
            </p>

        </div>

        <!-- STATUS MESSAGE -->
        <?php if ($flash): ?>

            <div class="ot-msg <?= escape($flash[0]) ?>">
                <?= escape($flash[1]) ?>
            </div>

        <?php endif; ?>

        <!-- STATISTICS -->
        <div class="ot-stats">

            <div class="dashboard-card ot-stat">

                <span class="muted">
                    Requests
                </span>

                <strong>
                    <?= $counts['total'] ?>
                </strong>

            </div>

            <div class="dashboard-card ot-stat">

                <span class="muted">
                    Pending
                </span>

                <strong>
                    <?= $counts['pending'] ?>
                </strong>

            </div>

            <div class="dashboard-card ot-stat">

                <span class="muted">
                    Approved
                </span>

                <strong>
                    <?= $counts['approved'] ?>
                </strong>

            </div>

        </div>

        <!-- =====================================
             EMPLOYEE REQUEST FORM
        ===================================== -->

        <?php if ($isEmployee): ?>

            <section class="dashboard-card ot-panel">

                <h2>Request Overtime</h2>

                <p class="ot-intro">
                    Select an overtime date and duration.
                    No completed shift is needed to submit
                    a request. HR/Admin must approve it
                    before it is considered authorized.
                </p>

                <?php if (
                    !$employeeProfile ||
                    $employeeProfile['employment_status']
                        !== 'Active'
                ): ?>

                    <div class="ot-msg error">
                        No active employee record is linked
                        to your login. Ask HR/Admin to link
                        or activate your employee profile.
                    </div>

                <?php else: ?>

                    <form
                        class="ot-form"
                        method="POST"
                        action="overtime.php"
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

                        <!-- OVERTIME DATE -->
                        <div class="ot-field">

                            <label for="otDate">
                                Overtime Date
                            </label>

                            <input
                                type="date"
                                name="requested_date"
                                id="otDate"
                                value="<?= date('Y-m-d') ?>"
                                required
                            >

                        </div>

                        <!-- OVERTIME DURATION -->
                        <div class="ot-field">

                            <label for="otDuration">
                                Overtime Duration
                            </label>

                            <select
                                name="requested_minutes"
                                id="otDuration"
                                required
                            >

                                <option value="">
                                    Choose duration
                                </option>

                                <?php for (
                                    $minutes = 15;
                                    $minutes <= 240;
                                    $minutes += 15
                                ): ?>

                                    <option
                                        value="<?= $minutes ?>"
                                    >
                                        <?= escape(
                                            otDuration($minutes)
                                        ) ?>
                                    </option>

                                <?php endfor; ?>

                            </select>

                        </div>

                        <!-- SUBMIT -->
                        <div class="ot-form-footer">

                            <p class="ot-intro">
                                This is an overtime
                                <strong>request</strong>,
                                not a clock-out record or
                                guaranteed overtime pay.
                                Actual overtime must be
                                checked against Attendance
                                during payroll processing.
                            </p>

                            <button
                                class="ot-btn"
                                type="submit"
                            >
                                Submit Overtime Request
                            </button>

                        </div>

                    </form>

                <?php endif; ?>

            </section>

        <?php endif; ?>

        <!-- =====================================
             OVERTIME REQUEST LIST
        ===================================== -->

        <section class="dashboard-card ot-panel">

            <h2>
                <?= $isHR
                    ? 'All Overtime Requests'
                    : 'My Overtime Requests' ?>
            </h2>

            <!-- SEARCH AND FILTER -->
            <div class="ot-tools">

                <input
                    id="otSearch"
                    type="search"
                    placeholder="Search name, date or duration..."
                    aria-label="Search overtime requests"
                >

                <select
                    id="otFilter"
                    aria-label="Filter by status"
                >

                    <option value="">
                        All Active Statuses
                    </option>

                    <option value="Pending">
                        Pending
                    </option>

                    <option value="Approved">
                        Approved
                    </option>

                    <option value="Rejected">
                        Rejected
                    </option>

                    <option value="Cancelled">
                        Cancelled
                    </option>

                    <?php if ($isHR): ?>

                        <option value="Archived">
                            Archived
                        </option>

                    <?php endif; ?>

                </select>

            </div>

            <!-- TABLE -->
            <div class="ot-scroll">

                <table
                    class="ot-table"
                    id="otTable"
                >

                    <thead>

                        <tr>

                            <?php if ($isHR): ?>
                                <th>Employee</th>
                            <?php endif; ?>

                            <th>Date</th>
                            <th>Requested Duration</th>
                            <th>Attendance Verification</th>
                            <th>Status</th>
                            <th>Actions</th>

                        </tr>

                    </thead>

                    <tbody>

                        <?php foreach (
                            $requests as $item
                        ): ?>

                            <?php
                            $archived =
                                $item['deleted_at'] !== null;

                            $actual = otActualMinutes($item);
                            ?>

                            <tr
                                data-status="<?= escape($item['status']) ?>"
                                data-archived="<?= $archived ? '1' : '0' ?>"
                            >

                                <!-- EMPLOYEE -->
                                <?php if ($isHR): ?>

                                    <td>

                                        <strong>
                                            <?= escape(
                                                $item['full_name']
                                            ) ?>
                                        </strong>

                                        <small>
                                            <?= escape(
                                                $item['employee_code']
                                            ) ?>

                                            ·

                                            <?= escape(
                                                (string) (
                                                    $item['department_name']
                                                        ?? 'Not assigned'
                                                )
                                            ) ?>
                                        </small>

                                    </td>

                                <?php endif; ?>

                                <!-- DATE -->
                                <td>

                                    <strong>
                                        <?= escape(
                                            date(
                                                'M d, Y',
                                                strtotime(
                                                    $item['requested_date']
                                                )
                                            )
                                        ) ?>
                                    </strong>

                                    <small>
                                        Requested:

                                        <?= escape(
                                            date(
                                                'M d, Y h:i A',
                                                strtotime(
                                                    $item['created_at']
                                                )
                                            )
                                        ) ?>
                                    </small>

                                </td>

                                <!-- DURATION -->
                                <td>

                                    <strong>
                                        <?= escape(
                                            otDuration(
                                                (int) $item['requested_minutes']
                                            )
                                        ) ?>
                                    </strong>

                                </td>

                                <!-- ATTENDANCE -->
                                <td>

                                    <?php if ($actual === null): ?>

                                        <span class="ot-tag Pending">
                                            Awaiting completed attendance
                                        </span>

                                    <?php else: ?>

                                        <strong>
                                            <?= escape(
                                                otDuration($actual)
                                            ) ?>
                                            recorded
                                        </strong>

                                        <?php if (
                                            $actual <
                                            (int) $item['requested_minutes']
                                        ): ?>

                                            <small>
                                                Less than requested;
                                                payroll must use
                                                actual verified
                                                minutes only.
                                            </small>

                                        <?php else: ?>

                                            <small>
                                                Recorded attendance
                                                covers requested duration.
                                            </small>

                                        <?php endif; ?>

                                    <?php endif; ?>

                                </td>

                                <!-- STATUS -->
                                <td>

                                    <span
                                        class="ot-tag <?= $archived
                                            ? 'Archived'
                                            : escape(
                                                $item['status']
                                            ) ?>"
                                    >
                                        <?= $archived
                                            ? 'Archived'
                                            : escape(
                                                $item['status']
                                            ) ?>
                                    </span>

                                    <?php if ($archived): ?>

                                        <small>
                                            Previous:
                                            <?= escape(
                                                $item['status']
                                            ) ?>
                                        </small>

                                    <?php endif; ?>

                                    <?php if (
                                        !empty($item['review_note'])
                                    ): ?>

                                        <small>
                                            HR note:
                                            <?= escape(
                                                $item['review_note']
                                            ) ?>
                                        </small>

                                    <?php endif; ?>

                                </td>

                                <!-- ACTIONS -->
                                <td>

                                    <div class="ot-actions">

                                        <?php if (
                                            $isHR &&
                                            !$archived &&
                                            $item['status'] === 'Pending'
                                        ): ?>

                                            <button
                                                type="button"
                                                class="ot-btn"
                                                data-id="<?= (int) $item['id'] ?>"
                                                data-name="<?= escape($item['full_name']) ?>"
                                                data-decision="Approved"
                                                onclick="openReview(this)"
                                            >
                                                Approve
                                            </button>

                                            <button
                                                type="button"
                                                class="ot-btn danger"
                                                data-id="<?= (int) $item['id'] ?>"
                                                data-name="<?= escape($item['full_name']) ?>"
                                                data-decision="Rejected"
                                                onclick="openReview(this)"
                                            >
                                                Reject
                                            </button>

                                        <?php elseif (
                                            $isEmployee &&
                                            $item['status'] === 'Pending'
                                        ): ?>

                                            <button
                                                type="button"
                                                class="ot-btn alt"
                                                data-id="<?= (int) $item['id'] ?>"
                                                onclick="openCancel(this)"
                                            >
                                                Cancel
                                            </button>

                                        <?php endif; ?>

                                        <?php if ($isHR): ?>

                                            <button
                                                type="button"
                                                class="ot-dots"
                                                aria-label="More actions"
                                                data-id="<?= (int) $item['id'] ?>"
                                                data-archived="<?= $archived ? '1' : '0' ?>"
                                                onclick="openActions(this)"
                                            >
                                                ⋮
                                            </button>

                                        <?php endif; ?>

                                    </div>

                                </td>

                            </tr>

                        <?php endforeach; ?>

                        <?php if (!$requests): ?>

                            <tr id="otEmpty">

                                <td
                                    colspan="<?= $isHR ? 6 : 5 ?>"
                                    class="ot-intro"
                                >
                                    No overtime requests yet.
                                </td>

                            </tr>

                        <?php endif; ?>

                    </tbody>

                </table>

            </div>

            <p class="ot-intro">
                Approved overtime requests are
                authorizations only. The Payroll
                module must verify completed
                attendance and apply applicable
                policies before calculating
                payable overtime.
            </p>

        </section>

    </main>

</div>

<!-- =====================================
     HR APPROVAL DIALOG
===================================== -->

<?php if ($isHR): ?>

<dialog
    class="ot-dialog"
    id="reviewDialog"
>

    <h3>Review Overtime Request</h3>

    <p id="reviewHeading"></p>

    <p class="ot-intro">
        Approval authorizes the requested overtime;
        it does not confirm that the hours have
        already been worked or paid.
    </p>

    <form
        method="POST"
        action="overtime.php"
    >

        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input
            type="hidden"
            name="action"
            value="review"
        >

        <input
            type="hidden"
            name="request_id"
            id="reviewId"
        >

        <input
            type="hidden"
            name="decision"
            id="reviewDecision"
        >

        <label for="reviewNote">
            HR Review Note
        </label>

        <textarea
            id="reviewNote"
            name="review_note"
            maxlength="255"
            placeholder="Optional for approval, required for rejection"
        ></textarea>

        <div class="ot-dialog-actions">

            <button
                class="ot-btn alt"
                type="button"
                onclick="document.getElementById('reviewDialog').close()"
            >
                Back
            </button>

            <button
                class="ot-btn"
                id="reviewSubmit"
                type="submit"
            >
                Confirm
            </button>

        </div>

    </form>

</dialog>

<!-- =====================================
     ARCHIVE / RESTORE ACTIONS
===================================== -->

<dialog
    class="ot-dialog"
    id="actionsDialog"
>

    <h3>Overtime Actions</h3>

    <p id="actionsText"></p>

    <p class="ot-intro">
        Delete archives the request.
        Restore returns an archived
        request to the list.
    </p>

    <div class="ot-dialog-actions">

        <button
            class="ot-btn alt"
            type="button"
            onclick="document.getElementById('actionsDialog').close()"
        >
            Back
        </button>

        <button
            class="ot-btn danger"
            id="actionsContinue"
            type="button"
        >
            Continue
        </button>

    </div>

</dialog>

<!-- =====================================
     ARCHIVE CONFIRMATION
===================================== -->

<dialog
    class="ot-dialog"
    id="archiveDialog"
>

    <h3 id="archiveTitle">
        Confirm Action
    </h3>

    <p id="archiveText"></p>

    <form
        method="POST"
        action="overtime.php"
    >

        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input
            type="hidden"
            name="action"
            id="archiveAction"
        >

        <input
            type="hidden"
            name="request_id"
            id="archiveId"
        >

        <div class="ot-dialog-actions">

            <button
                class="ot-btn alt"
                type="button"
                onclick="document.getElementById('archiveDialog').close()"
            >
                Back
            </button>

            <button
                class="ot-btn danger"
                id="archiveSubmit"
                type="submit"
            >
                Confirm
            </button>

        </div>

    </form>

</dialog>

<?php else: ?>

<!-- =====================================
     EMPLOYEE CANCEL DIALOG
===================================== -->

<dialog
    class="ot-dialog"
    id="cancelDialog"
>

    <h3>Cancel Overtime Request?</h3>

    <p>
        You may resubmit a cancelled
        request for the same date.
    </p>

    <form
        method="POST"
        action="overtime.php"
    >

        <input
            type="hidden"
            name="csrf_token"
            value="<?= escape(csrf_token()) ?>"
        >

        <input
            type="hidden"
            name="action"
            value="cancel"
        >

        <input
            type="hidden"
            name="request_id"
            id="cancelId"
        >

        <div class="ot-dialog-actions">

            <button
                class="ot-btn alt"
                type="button"
                onclick="document.getElementById('cancelDialog').close()"
            >
                Back
            </button>

            <button
                class="ot-btn danger"
                type="submit"
            >
                Yes, Cancel
            </button>

        </div>

    </form>

</dialog>

<?php endif; ?>

<!-- =====================================
     LOGOUT CONFIRMATION
===================================== -->

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
            action="../logout.php"
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

<!-- =====================================
     JAVASCRIPT
===================================== -->

<script>
// SIDEBAR COLLAPSE
const toggle = document.getElementById(
    'sidebarToggle'
);

if (toggle) {
    toggle.addEventListener('click', () => {
        document.body.classList.toggle('collapsed');
    });
}

// LOGOUT
const logout = document.getElementById(
    'openLogout'
);

if (logout) {
    logout.addEventListener('click', () => {
        document.getElementById(
            'logoutDialog'
        ).showModal();
    });
}

// SEARCH AND FILTER
const search = document.getElementById(
    'otSearch'
);

const filter = document.getElementById(
    'otFilter'
);

function filterRows() {

    const q = search.value
        .toLowerCase()
        .trim();

    const status = filter.value;

    document.querySelectorAll(
        '#otTable tbody tr[data-status]'
    ).forEach(row => {

        const archived =
            row.dataset.archived === '1';

        const matchStatus =
            status === 'Archived'
                ? archived
                : !archived && (
                    !status ||
                    row.dataset.status === status
                );

        row.hidden = !(
            matchStatus &&
            row.textContent
                .toLowerCase()
                .includes(q)
        );
    });
}

search.addEventListener(
    'input',
    filterRows
);

filter.addEventListener(
    'change',
    filterRows
);

filterRows();

// =====================================
// HR / ADMIN FUNCTIONS
// =====================================

<?php if ($isHR): ?>

function openReview(button) {

    const approved =
        button.dataset.decision === 'Approved';

    document.getElementById(
        'reviewId'
    ).value = button.dataset.id;

    document.getElementById(
        'reviewDecision'
    ).value = button.dataset.decision;

    document.getElementById(
        'reviewHeading'
    ).textContent =
        (approved ? 'Approve' : 'Reject') +
        ' request from ' +
        button.dataset.name +
        '?';

    const note = document.getElementById(
        'reviewNote'
    );

    note.value = '';
    note.required = !approved;
    note.minLength = approved ? 0 : 5;

    document.getElementById(
        'reviewSubmit'
    ).textContent = approved
        ? 'Approve'
        : 'Reject';

    document.getElementById(
        'reviewDialog'
    ).showModal();
}

let selectedRequest = null;

function openActions(button) {

    selectedRequest = {
        id: button.dataset.id,
        archived:
            button.dataset.archived === '1'
    };

    document.getElementById(
        'actionsText'
    ).textContent =
        'Request #' + selectedRequest.id;

    document.getElementById(
        'actionsContinue'
    ).textContent =
        selectedRequest.archived
            ? 'Restore'
            : 'Delete';

    document.getElementById(
        'actionsDialog'
    ).showModal();
}

document.getElementById(
    'actionsContinue'
).addEventListener('click', () => {

    if (!selectedRequest) {
        return;
    }

    const restore = selectedRequest.archived;

    document.getElementById(
        'archiveId'
    ).value = selectedRequest.id;

    document.getElementById(
        'archiveAction'
    ).value = restore
        ? 'restore'
        : 'archive';

    document.getElementById(
        'archiveTitle'
    ).textContent = restore
        ? 'Restore Request?'
        : 'Delete Request?';

    document.getElementById(
        'archiveText'
    ).textContent =
        (restore ? 'Restore' : 'Archive') +
        ' overtime request #' +
        selectedRequest.id +
        '?';

    document.getElementById(
        'archiveSubmit'
    ).textContent = restore
        ? 'Yes, Restore'
        : 'Yes, Delete';

    document.getElementById(
        'actionsDialog'
    ).close();

    document.getElementById(
        'archiveDialog'
    ).showModal();
});

<?php else: ?>

// EMPLOYEE CANCEL REQUEST
function openCancel(button) {

    document.getElementById(
        'cancelId'
    ).value = button.dataset.id;

    document.getElementById(
        'cancelDialog'
    ).showModal();
}

<?php endif; ?>
</script>

<!-- =====================================
     ACCOUNT INFORMATION WIDGET
===================================== -->

<?php
$widgetPath =
    __DIR__ . '/../includes/account_widget.php';

if (is_file($widgetPath)) {
    require $widgetPath;
}
?>

</body>
</html>
