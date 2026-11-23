
<?php
require_once __DIR__ . '/../includes/auth.php';

date_default_timezone_set('Asia/Manila');

$user = current_user();

if (!$user) {
    header('Location: ../index.php');
    exit;
}

$role = $user['role_name'];

$isHR = in_array(
    $role,
    ['administrator', 'hr_officer'],
    true
);

$isEmployee = $role === 'employee';

if (!$isHR && !$isEmployee) {
    http_response_code(403);
    exit('403 Forbidden: Attendance access denied.');
}

// AUDIT LOG
function attendance_log(
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

// DISPLAY DATE AND TIME
function display_time(?string $value): string {
    return $value
        ? date('M d, Y h:i A', strtotime($value))
        : '—';
}

// ATTENDANCE STATUS WITH APPROVED LEAVE
function attendance_status(
    array $shift,
    int $now
): string {

    if ($shift['time_in'] && $shift['time_out']) {
        return 'Completed';
    }

    if ($shift['time_in']) {
        return $now > strtotime($shift['ends_at']) + 86400
            ? 'Missing Time Out'
            : 'Clocked In';
    }

    if (!empty($shift['approved_leave_id'])) {
        return (int) $shift['leave_paid'] === 1
            ? 'Approved Paid Leave'
            : 'Approved Unpaid Leave';
    }

    if ($now > strtotime($shift['ends_at'])) {
        return 'Possible Absence';
    }

    return $now < strtotime($shift['starts_at'])
        ? 'Scheduled'
        : 'Awaiting Time In';
}

// VALIDATE MANUAL DATE AND TIME
function local_datetime(
    string $value
): ?DateTimeImmutable {

    if ($value === '') {
        return null;
    }

    $date = DateTimeImmutable::createFromFormat(
        '!Y-m-d\TH:i',
        $value,
        new DateTimeZone('Asia/Manila')
    );

    if (
        !$date ||
        $date->format('Y-m-d\TH:i') !== $value
    ) {
        throw new RuntimeException(
            'Enter a valid Time In / Time Out date and time.'
        );
    }

    return $date;
}

// PROCESS ALL FORM ACTIONS
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $kind = 'error';
    $message = 'Action failed.';

    try {

        if (!valid_csrf()) {
            throw new RuntimeException(
                'Invalid request. Refresh the page.'
            );
        }

        $action = (string) ($_POST['action'] ?? '');
        $actor = (int) $user['id'];

        $now = new DateTimeImmutable(
            'now',
            new DateTimeZone('Asia/Manila')
        );

        // ASSIGN EMPLOYEE SHIFT
        if ($action === 'schedule') {

            if (!$isHR) {
                throw new RuntimeException(
                    'Only HR/Admin can assign shifts.'
                );
            }

            $employeeId = filter_var(
                $_POST['employee_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            $dateText = (string) (
                $_POST['shift_date'] ?? ''
            );

            $startText = (string) (
                $_POST['start_time'] ?? ''
            );

            $endText = (string) (
                $_POST['end_time'] ?? ''
            );

            $date = DateTimeImmutable::createFromFormat(
                '!Y-m-d',
                $dateText
            );

            if (
                !$employeeId ||
                !$date ||
                $date->format('Y-m-d') !== $dateText
            ) {
                throw new RuntimeException(
                    'Select an employee and valid date.'
                );
            }

            if (
                !preg_match(
                    '/^(?:[01]\d|2[0-3]):[0-5]\d$/',
                    $startText
                ) ||
                !preg_match(
                    '/^(?:[01]\d|2[0-3]):[0-5]\d$/',
                    $endText
                )
            ) {
                throw new RuntimeException(
                    'Enter valid shift start and end times.'
                );
            }

            $start = new DateTimeImmutable(
                $dateText . ' ' . $startText
            );

            $end = new DateTimeImmutable(
                $dateText . ' ' . $endText
            );

            // SUPPORT OVERNIGHT SHIFTS
            if ($end <= $start) {
                $end = $end->modify('+1 day');
            }

            $hours = (
                $end->getTimestamp() -
                $start->getTimestamp()
            ) / 3600;

            if ($hours < 1 || $hours > 16) {
                throw new RuntimeException(
                    'Shift must be 1–16 hours.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                "SELECT user_id
                 FROM employees
                 WHERE id = ?
                   AND employment_status = 'Active'
                   AND deleted_at IS NULL
                 LIMIT 1"
            );

            $stmt->execute([$employeeId]);
            $employee = $stmt->fetch();

            if (!$employee) {
                throw new RuntimeException(
                    'Select an active employee.'
                );
            }

            $stmt = $pdo->prepare(
                'INSERT INTO employee_shifts
                 (
                    employee_id,
                    shift_date,
                    starts_at,
                    ends_at,
                    created_by
                 )
                 VALUES (?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $employeeId,
                $dateText,
                $start->format('Y-m-d H:i:s'),
                $end->format('Y-m-d H:i:s'),
                $actor
            ]);

            attendance_log(
                $pdo,
                $actor,
                $employee['user_id'] === null
                    ? null
                    : (int) $employee['user_id'],
                'SHIFT_ASSIGN',
                'Assigned shift for employee #' .
                    $employeeId . ' on ' . $dateText
            );

            $pdo->commit();

            $message = 'Shift assigned successfully.';
            $kind = 'success';

        // HR MANUAL TIME IN / TIME OUT
        } elseif ($action === 'manual_save') {

            if (!$isHR) {
                throw new RuntimeException(
                    'Only HR/Admin can enter attendance manually.'
                );
            }

            $shiftId = filter_var(
                $_POST['shift_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$shiftId) {
                throw new RuntimeException(
                    'Select a valid assigned shift.'
                );
            }

            $postedIn = local_datetime(trim(
                (string) ($_POST['manual_time_in'] ?? '')
            ));

            $postedOut = local_datetime(trim(
                (string) ($_POST['manual_time_out'] ?? '')
            ));

            if (!$postedIn && !$postedOut) {
                throw new RuntimeException(
                    'Enter Time In or Time Out.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT
                    s.starts_at,
                    s.ends_at,
                    e.user_id,
                    a.id AS attendance_id,
                    a.time_in,
                    a.time_out
                 FROM employee_shifts s
                 JOIN employees e
                   ON e.id = s.employee_id
                 LEFT JOIN attendance_records a
                   ON a.shift_id = s.id
                 WHERE s.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$shiftId]);
            $shift = $stmt->fetch();

            if (!$shift) {
                throw new RuntimeException(
                    'Assigned shift not found.'
                );
            }

            $in = $postedIn ?? (
                $shift['time_in']
                    ? new DateTimeImmutable($shift['time_in'])
                    : null
            );

            $out = $postedOut ?? (
                $shift['time_out']
                    ? new DateTimeImmutable($shift['time_out'])
                    : null
            );

            if (!$in) {
                throw new RuntimeException(
                    'A Time In is required before Time Out.'
                );
            }

            if ($out && $out <= $in) {
                throw new RuntimeException(
                    'Time Out must be later than Time In.'
                );
            }

            $lower = (
                new DateTimeImmutable($shift['starts_at'])
            )->modify('-4 hours');

            $upper = (
                new DateTimeImmutable($shift['ends_at'])
            )->modify('+24 hours');

            if (
                $in < $lower ||
                $in > $upper ||
                $in > $now ||
                (
                    $out &&
                    ($out > $upper || $out > $now)
                )
            ) {
                throw new RuntimeException(
                    'Attendance entries must be within the shift recording window and cannot be in the future.'
                );
            }

            if ($shift['attendance_id'] !== null) {

                $stmt = $pdo->prepare(
                    'UPDATE attendance_records
                     SET time_in = ?,
                         time_out = ?
                     WHERE id = ?'
                );

                $stmt->execute([
                    $in->format('Y-m-d H:i:s'),
                    $out
                        ? $out->format('Y-m-d H:i:s')
                        : null,
                    $shift['attendance_id']
                ]);

            } else {

                $stmt = $pdo->prepare(
                    'INSERT INTO attendance_records
                     (shift_id, time_in, time_out)
                     VALUES (?, ?, ?)'
                );

                $stmt->execute([
                    $shiftId,
                    $in->format('Y-m-d H:i:s'),
                    $out
                        ? $out->format('Y-m-d H:i:s')
                        : null
                ]);
            }

            attendance_log(
                $pdo,
                $actor,
                $shift['user_id'] === null
                    ? null
                    : (int) $shift['user_id'],
                'ATTENDANCE_MANUAL',
                'HR/Admin recorded or corrected attendance for shift #' .
                    $shiftId
            );

            $pdo->commit();

            $message =
                'Time In / Time Out saved successfully.';
            $kind = 'success';

        // DELETE UNRECORDED ASSIGNED SHIFT
        } elseif ($action === 'delete_shift') {

            if (!$isHR) {
                throw new RuntimeException(
                    'Only HR/Admin can delete assigned shifts.'
                );
            }

            $shiftId = filter_var(
                $_POST['shift_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$shiftId) {
                throw new RuntimeException(
                    'Invalid assigned shift.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                'SELECT
                    s.id,
                    s.employee_id,
                    s.shift_date,
                    s.starts_at,
                    s.ends_at,
                    e.full_name,
                    e.user_id,
                    a.id AS attendance_id
                 FROM employee_shifts s
                 JOIN employees e
                   ON e.id = s.employee_id
                 LEFT JOIN attendance_records a
                   ON a.shift_id = s.id
                 WHERE s.id = ?
                 FOR UPDATE'
            );

            $stmt->execute([$shiftId]);
            $shift = $stmt->fetch();

            if (!$shift) {
                throw new RuntimeException(
                    'Shift assignment not found.'
                );
            }

            if ($shift['attendance_id'] !== null) {
                throw new RuntimeException(
                    'Cannot delete a shift with recorded Time In/Out. Its attendance history must be preserved.'
                );
            }

            $stmt = $pdo->prepare(
                'DELETE FROM employee_shifts
                 WHERE id = ?'
            );

            $stmt->execute([$shiftId]);

            if ($stmt->rowCount() !== 1) {
                throw new RuntimeException(
                    'Shift could not be deleted.'
                );
            }

            attendance_log(
                $pdo,
                $actor,
                $shift['user_id'] === null
                    ? null
                    : (int) $shift['user_id'],
                'SHIFT_DELETE',
                'Deleted unrecorded shift #' .
                    $shiftId .
                    ' for employee #' .
                    $shift['employee_id'] .
                    ' on ' .
                    $shift['shift_date']
            );

            $pdo->commit();

            $message =
                'Assigned shift deleted successfully.';
            $kind = 'success';

        // EMPLOYEE TIME IN / TIME OUT
        } elseif (
            $action === 'clock_in' ||
            $action === 'clock_out'
        ) {

            if (!$isEmployee) {
                throw new RuntimeException(
                    'Only Employees can clock in/out for themselves.'
                );
            }

            $shiftId = filter_var(
                $_POST['shift_id'] ?? null,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 1]]
            );

            if (!$shiftId) {
                throw new RuntimeException(
                    'Invalid shift.'
                );
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                "SELECT
                    s.starts_at,
                    s.ends_at,
                    a.id AS attendance_id,
                    a.time_in,
                    a.time_out
                 FROM employee_shifts s
                 JOIN employees e
                   ON e.id = s.employee_id
                 LEFT JOIN attendance_records a
                   ON a.shift_id = s.id
                 WHERE s.id = ?
                   AND e.user_id = ?
                   AND e.employment_status = 'Active'
                   AND e.deleted_at IS NULL
                 FOR UPDATE"
            );

            $stmt->execute([
                $shiftId,
                $actor
            ]);

            $shift = $stmt->fetch();

            if (!$shift) {
                throw new RuntimeException(
                    'This shift does not belong to your active employee account.'
                );
            }

            $nowTs = $now->getTimestamp();
            $startTs = strtotime($shift['starts_at']);
            $endTs = strtotime($shift['ends_at']);

            if ($action === 'clock_in') {

                if ($shift['time_in']) {
                    throw new RuntimeException(
                        'Already timed in.'
                    );
                }

                if (
                    $nowTs < $startTs - 3600 ||
                    $nowTs > $endTs
                ) {
                    throw new RuntimeException(
                        'Time In opens 60 minutes before the shift and closes at shift end.'
                    );
                }

                $stmt = $pdo->prepare(
                    'INSERT INTO attendance_records
                     (shift_id, time_in)
                     VALUES (?, ?)'
                );

                $stmt->execute([
                    $shiftId,
                    $now->format('Y-m-d H:i:s')
                ]);

                $message = 'Time In recorded!';
                $audit = 'TIME_IN';

            } else {

                if (
                    !$shift['time_in'] ||
                    $shift['time_out']
                ) {
                    throw new RuntimeException(
                        'Time In is required; Time Out can be recorded once.'
                    );
                }

                if (
                    $nowTs < strtotime($shift['time_in']) ||
                    $nowTs > $endTs + 86400
                ) {
                    throw new RuntimeException(
                        'Time Out is outside the allowed window.'
                    );
                }

                $stmt = $pdo->prepare(
                    'UPDATE attendance_records
                     SET time_out = ?
                     WHERE shift_id = ?
                       AND time_out IS NULL'
                );

                $stmt->execute([
                    $now->format('Y-m-d H:i:s'),
                    $shiftId
                ]);

                if ($stmt->rowCount() !== 1) {
                    throw new RuntimeException(
                        'Time Out could not be recorded.'
                    );
                }

                $message = 'Time Out recorded!';
                $audit = 'TIME_OUT';
            }

            attendance_log(
                $pdo,
                $actor,
                $actor,
                $audit,
                'Employee attendance for shift #' .
                    $shiftId
            );

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
            ? 'Employee already has a shift that date, or attendance already recorded.'
            : 'Database error. Check Attendance tables.';

    } catch (Throwable $e) {

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log($e->getMessage());

        $message =
            'Something went wrong. Please try again.';
    }

    $_SESSION['attendance_flash'] = [
        'kind' => $kind,
        'message' => $message
    ];

    header('Location: attendance.php', true, 303);
    exit;
}

// LOAD FLASH MESSAGE
$flash = $_SESSION['attendance_flash'] ?? null;
unset($_SESSION['attendance_flash']);

$employees = [];

// LOAD ATTENDANCE RECORDS WITH APPROVED LEAVE
if ($isHR) {

    $employees = $pdo->query(
        "SELECT
            id,
            employee_code,
            full_name
         FROM employees
         WHERE employment_status = 'Active'
           AND deleted_at IS NULL
         ORDER BY full_name"
    )->fetchAll();

    $shifts = $pdo->query(
        "SELECT
            s.*,
            e.full_name,
            e.employee_code,
            d.department_name,
            a.time_in,
            a.time_out,
            lr.id AS approved_leave_id,
            lr.is_paid AS leave_paid
         FROM employee_shifts s
         JOIN employees e
           ON e.id = s.employee_id
         JOIN departments d
           ON d.id = e.department_id
         LEFT JOIN attendance_records a
           ON a.shift_id = s.id
         LEFT JOIN leave_requests lr
           ON lr.employee_id = s.employee_id
          AND lr.status = 'Approved'
          AND lr.deleted_at IS NULL
          AND s.shift_date BETWEEN
              lr.start_date AND lr.end_date
         ORDER BY s.shift_date DESC, s.id DESC
         LIMIT 200"
    )->fetchAll();

} else {

    $stmt = $pdo->prepare(
        "SELECT
            s.*,
            e.full_name,
            e.employee_code,
            d.department_name,
            a.time_in,
            a.time_out,
            lr.id AS approved_leave_id,
            lr.is_paid AS leave_paid
         FROM employee_shifts s
         JOIN employees e
           ON e.id = s.employee_id
         JOIN departments d
           ON d.id = e.department_id
         LEFT JOIN attendance_records a
           ON a.shift_id = s.id
         LEFT JOIN leave_requests lr
           ON lr.employee_id = s.employee_id
          AND lr.status = 'Approved'
          AND lr.deleted_at IS NULL
          AND s.shift_date BETWEEN
              lr.start_date AND lr.end_date
         WHERE e.user_id = ?
           AND e.employment_status = 'Active'
           AND e.deleted_at IS NULL
         ORDER BY s.shift_date DESC, s.id DESC
         LIMIT 200"
    );

    $stmt->execute([(int) $user['id']]);
    $shifts = $stmt->fetchAll();
}

// ATTENDANCE SUMMARY
$nowTs = time();
$complete = 0;
$possibleAbsence = 0;
$nextShift = null;

foreach ($shifts as $s) {

    $state = attendance_status($s, $nowTs);

    if ($state === 'Completed') {
        $complete++;
    }

    if ($state === 'Possible Absence') {
        $possibleAbsence++;
    }

    if (
        $isEmployee &&
        !$nextShift &&
        $nowTs >= strtotime($s['starts_at']) - 3600 &&
        $nowTs <= strtotime($s['ends_at']) + 86400
    ) {
        $nextShift = $s;
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
    Attendance | McDonald's San Pedro Bayan
</title>

<link rel="stylesheet" href="../css/style.css">

<style>
.att-title {
    margin: 28px 0 20px;
}

.att-title h1 {
    font-size: 32px;
    margin: 0 0 7px;
}

.att-stats {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin: 20px 0;
}

.att-stats strong {
    display: block;
    font-size: 31px;
    color: var(--green-dark);
    margin-top: 7px;
}

.att-panel {
    margin-bottom: 20px;
}

.att-panel h2 {
    font-size: 23px;
    margin: 0 0 12px;
}

.att-form {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.att-field label {
    display: block;
    font-weight: 600;
    margin-bottom: 8px;
    font-size: 16px;
}

.att-field input,
.att-field select {
    width: 100%;
    min-height: 47px;
    padding: 11px;
    border: 1px solid var(--border);
    border-radius: 9px;
    background: white;
    color: var(--text);
}

.att-field.wide {
    grid-column: 1 / -1;
}

.att-btn {
    background: var(--green);
    color: white;
    border: 0;
    border-radius: 9px;
    min-height: 46px;
    padding: 11px 19px;
    font-size: 16px;
    font-weight: 700;
    cursor: pointer;
}

.att-btn:hover {
    background: var(--green-dark);
}

.att-btn.alt {
    background: var(--light-green);
    color: var(--green-dark);
}

.att-btn:disabled {
    opacity: .55;
    cursor: not-allowed;
}

.att-table-wrap {
    overflow-x: auto;
}

.att-table {
    width: 100%;
    min-width: 850px;
    border-collapse: collapse;
}

.att-table th,
.att-table td {
    padding: 14px 10px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: middle;
    font-size: 15px;
}

.att-table th {
    color: var(--muted);
}

.att-table small {
    display: block;
    color: var(--muted);
    margin-top: 5px;
}

.att-tag {
    display: inline-block;
    padding: 7px 11px;
    border-radius: 20px;
    background: var(--light-green);
    color: var(--green-dark);
    font-weight: 700;
    font-size: 13px;
}

.att-tag.warn {
    background: #f9f0d9;
    color: #795b20;
}

.att-tag.danger {
    background: #f9e7e7;
    color: #9b3434;
}

.att-tag.leave {
    background: #e6f0e7;
    color: #526d57;
}

.att-notice {
    padding: 14px 16px;
    border-radius: 10px;
    margin: 15px 0;
}

.att-notice.success {
    background: var(--light-green);
    color: var(--green-dark);
}

.att-notice.error {
    background: #f9e7e7;
    color: #9b3434;
}

.att-note {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
}

.clock-box {
    padding: 18px;
    border: 1px solid var(--border);
    border-radius: 13px;
    background: #f5f7f4;
}

.clock-box strong {
    font-size: 18px;
}

.clock-box form {
    margin-top: 12px;
}

/* THREE-DOT MENU */
.dots-btn {
    width: 38px;
    height: 38px;
    border-radius: 9px;
    border: 1px solid var(--border);
    background: var(--light-green);
    color: var(--green-dark);
    font-size: 25px;
    font-weight: bold;
    cursor: pointer;
    line-height: 1;
}

.dots-btn:hover {
    background: #d7e7d9;
}

.shift-delete-btn {
    background: #f9e7e7;
    color: #9b3434;
    border: 1px solid #f0c9c9;
}

.shift-delete-btn:hover {
    background: #f4d7d7;
}

.shift-delete-btn:disabled {
    opacity: .5;
    cursor: not-allowed;
}

.dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    align-items: center;
    margin-top: 20px;
    flex-wrap: wrap;
}

.dialog-actions form {
    margin: 0;
}

@media (max-width: 720px) {
    .att-stats,
    .att-form {
        grid-template-columns: 1fr;
    }

    .att-field.wide {
        grid-column: auto;
    }

    .att-title h1 {
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
            class="sidebar-item active"
        >
            <span class="sidebar-icon">◷</span>
            <span class="sidebar-text">
                <?= $isHR
                    ? 'Attendance'
                    : 'My Attendance' ?>
            </span>
        </a>

        <!-- LEAVE MANAGEMENT LINK -->
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

        <div class="att-title">

            <h1>
                <?= $isHR
                    ? 'Attendance Management'
                    : 'My Attendance' ?>
            </h1>

            <p class="muted">
                <?= $isHR
                    ? 'Assign shifts and enter employee Time In / Time Out.'
                    : 'View your shift and record your own Time In / Time Out.' ?>
            </p>

        </div>

        <?php if ($flash): ?>

            <div class="att-notice <?= escape(
                $flash['kind']
            ) ?>">
                <?= escape($flash['message']) ?>
            </div>

        <?php endif; ?>

        <!-- SUMMARY CARDS -->
        <div class="att-stats">

            <div class="dashboard-card">
                <span class="muted">
                    Displayed Shifts
                </span>

                <strong>
                    <?= count($shifts) ?>
                </strong>
            </div>

            <div class="dashboard-card">
                <span class="muted">
                    Completed
                </span>

                <strong>
                    <?= $complete ?>
                </strong>
            </div>

            <div class="dashboard-card">
                <span class="muted">
                    Possible Absences
                </span>

                <strong>
                    <?= $possibleAbsence ?>
                </strong>
            </div>

        </div>

        <?php if ($isHR): ?>

            <!-- ASSIGN EMPLOYEE SHIFT -->
            <section class="dashboard-card att-panel">

                <h2>1. Assign Employee Shift</h2>

                <form
                    class="att-form"
                    action="attendance.php"
                    method="POST"
                >

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= escape(csrf_token()) ?>"
                    >

                    <input
                        type="hidden"
                        name="action"
                        value="schedule"
                    >

                    <div class="att-field">

                        <label for="employee">
                            Employee
                        </label>

                        <select
                            id="employee"
                            name="employee_id"
                            required
                        >

                            <option value="">
                                Select Employee
                            </option>

                            <?php foreach ($employees as $e): ?>

                                <option value="<?= (int) $e['id'] ?>">
                                    <?= escape(
                                        $e['full_name'] .
                                        ' (' .
                                        $e['employee_code'] .
                                        ')'
                                    ) ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <div class="att-field">

                        <label for="shiftDate">
                            Shift Date
                        </label>

                        <input
                            id="shiftDate"
                            type="date"
                            name="shift_date"
                            value="<?= date('Y-m-d') ?>"
                            required
                        >

                    </div>

                    <div class="att-field">

                        <label for="startTime">
                            Start Time
                        </label>

                        <input
                            id="startTime"
                            type="time"
                            name="start_time"
                            required
                        >

                    </div>

                    <div class="att-field">

                        <label for="endTime">
                            End Time
                        </label>

                        <input
                            id="endTime"
                            type="time"
                            name="end_time"
                            required
                        >

                    </div>

                    <div class="att-field wide">

                        <button
                            class="att-btn"
                            type="submit"
                        >
                            Assign Shift
                        </button>

                    </div>

                </form>

                <p class="att-note">
                    One assigned shift per employee
                    per day in this prototype.
                    Overnight shifts are supported.
                </p>

            </section>

            <!-- HR MANUAL ATTENDANCE -->
            <section class="dashboard-card att-panel">

                <h2>2. Enter Time In / Time Out</h2>

                <p class="att-note">
                    HR/Admin can record or correct actual
                    attendance for an assigned shift.
                    Leave fields blank to keep existing values.
                </p>

                <form
                    class="att-form"
                    action="attendance.php"
                    method="POST"
                >

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= escape(csrf_token()) ?>"
                    >

                    <input
                        type="hidden"
                        name="action"
                        value="manual_save"
                    >

                    <div class="att-field wide">

                        <label for="manualShift">
                            Employee / Assigned Shift
                        </label>

                        <select
                            id="manualShift"
                            name="shift_id"
                            required
                        >

                            <option value="">
                                Select assigned shift
                            </option>

                            <?php foreach ($shifts as $s): ?>

                                <option value="<?= (int) $s['id'] ?>">
                                    <?= escape(
                                        $s['full_name'] .
                                        ' (' .
                                        $s['employee_code'] .
                                        ') — ' .
                                        display_time(
                                            $s['starts_at']
                                        )
                                    ) ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <div class="att-field">

                        <label for="manualTimeIn">
                            Actual Time In
                        </label>

                        <input
                            id="manualTimeIn"
                            type="datetime-local"
                            name="manual_time_in"
                        >

                    </div>

                    <div class="att-field">

                        <label for="manualTimeOut">
                            Actual Time Out
                        </label>

                        <input
                            id="manualTimeOut"
                            type="datetime-local"
                            name="manual_time_out"
                        >

                    </div>

                    <div class="att-field wide">

                        <button
                            class="att-btn"
                            type="submit"
                        >
                            Save Time In / Time Out
                        </button>

                    </div>

                </form>

            </section>

        <?php elseif ($isEmployee): ?>

            <!-- EMPLOYEE TIME IN / OUT -->
            <section class="dashboard-card att-panel">

                <h2>Time In / Time Out</h2>

                <?php if ($nextShift): ?>

                    <div class="clock-box">

                        <strong>
                            <?= escape(
                                display_time(
                                    $nextShift['starts_at']
                                )
                            ) ?>
                            —
                            <?= escape(
                                display_time(
                                    $nextShift['ends_at']
                                )
                            ) ?>
                        </strong>

                        <p class="att-note">
                            Time In:
                            <?= escape(
                                display_time(
                                    $nextShift['time_in']
                                )
                            ) ?>

                            · Time Out:
                            <?= escape(
                                display_time(
                                    $nextShift['time_out']
                                )
                            ) ?>
                        </p>

                        <?php
                        $canIn =
                            !$nextShift['time_in'] &&
                            $nowTs >= strtotime(
                                $nextShift['starts_at']
                            ) - 3600 &&
                            $nowTs <= strtotime(
                                $nextShift['ends_at']
                            );

                        $canOut =
                            $nextShift['time_in'] &&
                            !$nextShift['time_out'] &&
                            $nowTs >= strtotime(
                                $nextShift['time_in']
                            ) &&
                            $nowTs <= strtotime(
                                $nextShift['ends_at']
                            ) + 86400;
                        ?>

                        <?php if ($canIn || $canOut): ?>

                            <form
                                method="POST"
                                action="attendance.php"
                            >

                                <input
                                    type="hidden"
                                    name="csrf_token"
                                    value="<?= escape(
                                        csrf_token()
                                    ) ?>"
                                >

                                <input
                                    type="hidden"
                                    name="shift_id"
                                    value="<?= (int) $nextShift['id'] ?>"
                                >

                                <input
                                    type="hidden"
                                    name="action"
                                    value="<?= $canIn
                                        ? 'clock_in'
                                        : 'clock_out' ?>"
                                >

                                <button
                                    class="att-btn <?= $canOut ? 'alt' : '' ?>"
                                    type="submit"
                                >
                                    <?= $canIn
                                        ? 'Time In Now'
                                        : 'Time Out Now' ?>
                                </button>

                            </form>

                        <?php else: ?>

                            <p class="att-note">
                                Time In/Out is not available
                                for this shift right now,
                                or attendance is completed.
                            </p>

                        <?php endif; ?>

                    </div>

                <?php else: ?>

                    <p class="att-note">
                        No shift currently inside its
                        clocking window. Your HR Officer
                        must assign your schedule and
                        link your Employee account.
                    </p>

                <?php endif; ?>

            </section>

        <?php endif; ?>

        <!-- ATTENDANCE RECORDS -->
        <section class="dashboard-card att-panel">

            <h2>
                <?= $isHR
                    ? 'Attendance Records'
                    : 'My Shift History' ?>
            </h2>

            <div class="att-table-wrap">

                <table class="att-table">

                    <thead>
                        <tr>

                            <?php if ($isHR): ?>
                                <th>Employee</th>
                            <?php endif; ?>

                            <th>Scheduled Shift</th>
                            <th>Time In</th>
                            <th>Time Out</th>
                            <th>Late</th>
                            <th>Hours</th>
                            <th>Status</th>

                            <?php if ($isHR): ?>
                                <th>Actions</th>
                            <?php endif; ?>

                        </tr>
                    </thead>

                    <tbody>

                    <?php foreach ($shifts as $s): ?>

                        <?php
                        $state = attendance_status(
                            $s,
                            $nowTs
                        );

                        $in = $s['time_in']
                            ? strtotime($s['time_in'])
                            : null;

                        $out = $s['time_out']
                            ? strtotime($s['time_out'])
                            : null;

                        $late = $in
                            ? max(
                                0,
                                (int) floor(
                                    (
                                        $in -
                                        strtotime($s['starts_at'])
                                    ) / 60
                                )
                            ) . ' min'
                            : '—';

                        $hours = $in && $out
                            ? number_format(
                                max(
                                    0,
                                    ($out - $in) / 3600
                                ),
                                2
                            ) . ' hrs'
                            : '—';

                        $tag = in_array(
                            $state,
                            [
                                'Possible Absence',
                                'Missing Time Out'
                            ],
                            true
                        )
                            ? 'danger'
                            : (
                                in_array(
                                    $state,
                                    [
                                        'Clocked In',
                                        'Awaiting Time In'
                                    ],
                                    true
                                )
                                    ? 'warn'
                                    : (
                                        str_starts_with(
                                            $state,
                                            'Approved '
                                        )
                                            ? 'leave'
                                            : ''
                                    )
                            );
                        ?>

                        <tr>

                            <?php if ($isHR): ?>

                                <td>
                                    <strong>
                                        <?= escape(
                                            $s['full_name']
                                        ) ?>
                                    </strong>

                                    <small>
                                        <?= escape(
                                            $s['employee_code'] .
                                            ' · ' .
                                            $s['department_name']
                                        ) ?>
                                    </small>
                                </td>

                            <?php endif; ?>

                            <td>
                                <?= escape(
                                    display_time(
                                        $s['starts_at']
                                    )
                                ) ?>

                                <small>
                                    to
                                    <?= escape(
                                        display_time(
                                            $s['ends_at']
                                        )
                                    ) ?>
                                </small>
                            </td>

                            <td>
                                <?= escape(
                                    display_time(
                                        $s['time_in']
                                    )
                                ) ?>
                            </td>

                            <td>
                                <?= escape(
                                    display_time(
                                        $s['time_out']
                                    )
                                ) ?>
                            </td>

                            <td><?= $late ?></td>
                            <td><?= $hours ?></td>

                            <td>
                                <span class="att-tag <?= $tag ?>">
                                    <?= escape($state) ?>
                                </span>
                            </td>

                            <?php if ($isHR): ?>

                                <td>
                                    <button
                                        type="button"
                                        class="dots-btn"
                                        aria-label="Shift actions"
                                        data-id="<?= (int) $s['id'] ?>"
                                        data-label="<?= escape(
                                            $s['full_name'] .
                                            ' — ' .
                                            display_time(
                                                $s['starts_at']
                                            )
                                        ) ?>"
                                        data-recorded="<?= (
                                            $s['time_in'] !== null ||
                                            $s['time_out'] !== null
                                        ) ? '1' : '0' ?>"
                                        onclick="openShiftActions(this)"
                                    >
                                        ⋮
                                    </button>
                                </td>

                            <?php endif; ?>

                        </tr>

                    <?php endforeach; ?>

                    <?php if (!$shifts): ?>

                        <tr>
                            <td
                                colspan="<?= $isHR ? 8 : 6 ?>"
                                class="muted"
                            >
                                No assigned shifts yet.
                            </td>
                        </tr>

                    <?php endif; ?>

                    </tbody>

                </table>

            </div>

            <p class="att-note">
                Philippine time. Approved full-day
                leave is shown as Paid or Unpaid
                instead of Possible Absence.
                Hours do not yet subtract meal
                breaks or calculate approved overtime.
                Latest 200 shifts shown.
            </p>

        </section>

    </main>
</div>

<?php if ($isHR): ?>

<!-- THREE-DOT ACTIONS -->
<dialog
    class="confirm-dialog"
    id="shiftActionsDialog"
>

    <h3>Shift Actions</h3>

    <p id="shiftActionsLabel"></p>
    <p
        class="att-note"
        id="shiftActionsNote"
    ></p>

    <div class="dialog-actions">

        <button
            type="button"
            class="dialog-btn"
            id="cancelShiftActions"
        >
            Cancel
        </button>

        <button
            type="button"
            class="dialog-btn shift-delete-btn"
            id="openDeleteConfirm"
        >
            Delete
        </button>

    </div>

</dialog>

<!-- DELETE CONFIRMATION -->
<dialog
    class="confirm-dialog"
    id="deleteShiftDialog"
>

    <h3>Delete Assigned Shift?</h3>

    <p id="deleteShiftLabel"></p>

    <p class="att-note">
        This removes the unrecorded
        assigned shift. The action will
        be saved in audit logs.
    </p>

    <div class="dialog-actions">

        <button
            type="button"
            class="dialog-btn"
            id="cancelDeleteShift"
        >
            Cancel
        </button>

        <form
            method="POST"
            action="attendance.php"
        >

            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape(csrf_token()) ?>"
            >

            <input
                type="hidden"
                name="action"
                value="delete_shift"
            >

            <input
                type="hidden"
                name="shift_id"
                id="deleteShiftId"
            >

            <button
                type="submit"
                class="dialog-btn shift-delete-btn"
            >
                Yes, Delete
            </button>

        </form>

    </div>

</dialog>

<?php endif; ?>

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
            action="../logout.php"
            method="POST"
        >

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
    .addEventListener('click', function () {
        document.body.classList.toggle('collapsed');
    });

// LOGOUT CONFIRMATION
document.getElementById('openLogout')
    .addEventListener('click', function () {
        document.getElementById('logoutDialog')
            .showModal();
    });

<?php if ($isHR): ?>

// THREE-DOT MENU
const shiftActionsDialog =
    document.getElementById('shiftActionsDialog');

const deleteShiftDialog =
    document.getElementById('deleteShiftDialog');

const deleteOption =
    document.getElementById('openDeleteConfirm');

let pendingShiftId = '';
let pendingShiftLabel = '';

function openShiftActions(button) {

    pendingShiftId = button.dataset.id;
    pendingShiftLabel = button.dataset.label;

    const recorded =
        button.dataset.recorded === '1';

    document.getElementById(
        'shiftActionsLabel'
    ).textContent = pendingShiftLabel;

    document.getElementById(
        'shiftActionsNote'
    ).textContent = recorded
        ? 'This shift already has recorded attendance. Deletion is disabled to protect payroll records.'
        : 'No Time In/Out has been recorded. You can delete this mistaken assignment.';

    deleteOption.disabled = recorded;

    shiftActionsDialog.showModal();
}

// CANCEL ACTIONS
document.getElementById('cancelShiftActions')
    .addEventListener('click', function () {
        shiftActionsDialog.close();
    });

// OPEN DELETE CONFIRMATION
deleteOption.addEventListener('click', function () {

    shiftActionsDialog.close();

    document.getElementById(
        'deleteShiftId'
    ).value = pendingShiftId;

    document.getElementById(
        'deleteShiftLabel'
    ).textContent = pendingShiftLabel;

    deleteShiftDialog.showModal();
});

// CANCEL DELETE
document.getElementById('cancelDeleteShift')
    .addEventListener('click', function () {
        deleteShiftDialog.close();
    });

<?php endif; ?>
</script>


<?php require __DIR__ . '/../includes/account_widget.php'; ?>
</body>

</html>
