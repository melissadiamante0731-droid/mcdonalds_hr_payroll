
<?php
require_once __DIR__ . '/includes/auth.php';

if (current_user()) {
    header('Location: dashboard.php');
    exit;
}

$view = ($_GET['view'] ?? 'login') === 'signup'
    ? 'signup'
    : 'login';

$errors = [];
$fullName = '';
$email = '';
$selectedOpening = '';

// LOAD CURRENTLY OPEN POSITIONS
$openings = $pdo->query(
    'SELECT o.id,
            p.position_name,
            d.id AS department_id,
            d.department_name
     FROM job_openings o
     JOIN positions p
       ON p.id = o.position_id
     JOIN departments d
       ON d.id = p.department_id
     WHERE o.is_open = 1
       AND d.is_active = 1
     ORDER BY d.department_name,
              p.position_name'
)->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $action = (string) ($_POST['action'] ?? '');

    $view = $action === 'signup'
        ? 'signup'
        : 'login';

    $email = strtolower(trim(
        (string) ($_POST['email'] ?? '')
    ));

    if (!valid_csrf()) {

        $errors[] =
            'Invalid request. Refresh the page.';

    } elseif ($action === 'login') {

        $password = (string) (
            $_POST['password'] ?? ''
        );

        $lockUntil = (int) (
            $_SESSION['lock_until'] ?? 0
        );

        if ($lockUntil > time()) {

            $errors[] =
                'Too many attempts. Try again in 15 minutes.';

        } else {

            if ($lockUntil > 0) {
                unset($_SESSION['lock_until']);
                $_SESSION['failed_login'] = 0;
            }

            $stmt = $pdo->prepare(
                'SELECT id, password_hash
                 FROM users
                 WHERE email = ?
                   AND is_active = 1
                 LIMIT 1'
            );

            $stmt->execute([$email]);
            $account = $stmt->fetch();

            if (
                $account &&
                password_verify(
                    $password,
                    $account['password_hash']
                )
            ) {

                unset(
                    $_SESSION['failed_login'],
                    $_SESSION['lock_until']
                );

                sign_in((int) $account['id']);

                header('Location: dashboard.php');
                exit;
            }

            $_SESSION['failed_login'] =
                (int) (
                    $_SESSION['failed_login'] ?? 0
                ) + 1;

            if ($_SESSION['failed_login'] >= 5) {

                $_SESSION['lock_until'] =
                    time() + 900;

                $errors[] =
                    'Too many attempts. Try again in 15 minutes.';

            } else {

                $errors[] =
                    'Invalid email or password.';
            }
        }

    } elseif ($action === 'signup') {

        $fullName = trim(
            (string) ($_POST['full_name'] ?? '')
        );

        $password = (string) (
            $_POST['password'] ?? ''
        );

        $confirm = (string) (
            $_POST['confirm_password'] ?? ''
        );

        $selectedOpening = (string) (
            $_POST['job_opening_id'] ?? ''
        );

        $openingId = filter_var(
            $selectedOpening,
            FILTER_VALIDATE_INT
        );

        // VALIDATION
        if (
            strlen($fullName) < 2 ||
            strlen($fullName) > 150
        ) {
            $errors[] =
                'Enter a valid full name.';
        }

        if (
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            strlen($email) > 150
        ) {
            $errors[] =
                'Enter a valid email address.';
        }

        if (
            !$openingId ||
            $openingId < 1
        ) {
            $errors[] =
                'Select an available hiring position.';
        }

        if (
            strlen($password) < 12 ||
            strlen($password) > 72 ||
            !preg_match('/[A-Z]/', $password) ||
            !preg_match('/[a-z]/', $password) ||
            !preg_match('/[0-9]/', $password) ||
            !preg_match('/[^A-Za-z0-9]/', $password)
        ) {
            $errors[] =
                'Use 12-72 password characters with uppercase, lowercase, number and symbol.';
        }

        if ($password !== $confirm) {
            $errors[] =
                'Passwords do not match.';
        }

        if (!$errors) {

            try {
                $pdo->beginTransaction();

                // CHECK IF POSITION IS STILL OPEN
                $stmt = $pdo->prepare(
                    'SELECT p.position_name
                     FROM job_openings o
                     JOIN positions p
                       ON p.id = o.position_id
                     JOIN departments d
                       ON d.id = p.department_id
                     WHERE o.id = ?
                       AND o.is_open = 1
                       AND d.is_active = 1
                     FOR UPDATE'
                );

                $stmt->execute([
                    (int) $openingId
                ]);

                $position = $stmt->fetchColumn();

                if (!$position) {
                    throw new RuntimeException(
                        'This position is no longer open. Choose another.'
                    );
                }

                // APPLICANT ROLE ONLY
                $stmt = $pdo->prepare(
                    "SELECT id
                     FROM roles
                     WHERE role_name = 'applicant'
                     LIMIT 1"
                );

                $stmt->execute();

                $roleId = $stmt->fetchColumn();

                if (!$roleId) {
                    throw new RuntimeException(
                        'Applicant registration is unavailable.'
                    );
                }

                // CREATE APPLICANT ACCOUNT
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
                    $fullName,
                    $email,
                    password_hash(
                        $password,
                        PASSWORD_DEFAULT
                    ),
                    (int) $roleId
                ]);

                $userId = (int) $pdo->lastInsertId();

                // SAVE JOB APPLICATION
                $stmt = $pdo->prepare(
                    'INSERT INTO job_applications
                     (
                        user_id,
                        job_opening_id,
                        position_applied
                     )
                     VALUES (?, ?, ?)'
                );

                $stmt->execute([
                    $userId,
                    (int) $openingId,
                    $position
                ]);

                // RECORD AUDIT EVENT
                $stmt = $pdo->prepare(
                    'INSERT INTO audit_logs
                     (
                        actor_user_id,
                        target_user_id,
                        action,
                        details
                     )
                     VALUES (?, ?, ?, ?)'
                );

                $stmt->execute([
                    $userId,
                    $userId,
                    'APPLICANT_REGISTER',
                    'Applicant submitted an online application.'
                ]);

                $pdo->commit();

                sign_in($userId);

                header('Location: dashboard.php');
                exit;

            } catch (RuntimeException $e) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                $errors[] = $e->getMessage();

            } catch (PDOException $e) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log($e->getMessage());

                $errors[] = $e->getCode() === '23000'
                    ? 'This email is already registered.'
                    : 'Registration failed. Please try again.';

            } catch (Throwable $e) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log($e->getMessage());

                $errors[] =
                    'Registration failed. Please try again.';
            }
        }

    } else {

        $errors[] = 'Invalid action.';
    }
}

// BUILD DEPARTMENT DROPDOWN FROM OPEN JOBS ONLY
$availableDepartments = [];
$selectedDepartment = '';

foreach ($openings as $opening) {

    $availableDepartments[
        (int) $opening['department_id']
    ] = $opening['department_name'];

    if (
        $selectedOpening === (string) $opening['id']
    ) {
        $selectedDepartment =
            (string) $opening['department_id'];
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
    McDonald's San Pedro Bayan | HR & Payroll
</title>

<link rel="stylesheet" href="css/style.css">
</head>

<body class="auth-page">

<div class="auth-wrapper">

    <section class="brand-panel">

        <div class="brand-tag">
            HR & PAYROLL SYSTEM
        </div>

        <h1>
            McDonald's<br>
            San Pedro Bayan
        </h1>

        <p>
            Employee Management, Recruitment,
            Attendance and Payroll.
        </p>

        <div class="brand-note">
            Branch Management Portal · Academic Prototype
        </div>

    </section>

    <section class="form-panel">

        <div class="form-heading">

            <div class="small-brand">
                McDonald's San Pedro Bayan
            </div>

            <?php if ($view === 'login'): ?>

                <h2>Welcome Back!</h2>

                <p>
                    Sign in to access your dashboard.
                </p>

            <?php else: ?>

                <h2>Apply With Us</h2>

                <p>
                    Sign up to apply for a currently
                    available position.
                </p>

            <?php endif; ?>

        </div>

        <?php if (isset($_GET['logged_out'])): ?>

            <div class="success-box">
                You have successfully logged out.
            </div>

        <?php endif; ?>

        <?php if ($errors): ?>

            <div class="error-box">

                <?php foreach ($errors as $error): ?>

                    <p><?= escape($error) ?></p>

                <?php endforeach; ?>

            </div>

        <?php endif; ?>

        <?php if ($view === 'login'): ?>

            <!-- LOGIN FORM -->

            <form method="POST" action="index.php">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= escape(csrf_token()) ?>"
                >

                <input
                    type="hidden"
                    name="action"
                    value="login"
                >

                <label for="email">
                    Email Address
                </label>

                <input
                    type="email"
                    id="email"
                    name="email"
                    value="<?= escape($email) ?>"
                    placeholder="Enter your email"
                    required
                >

                <label for="password">
                    Password
                </label>

                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter your password"
                    required
                >

                <button
                    type="submit"
                    class="primary-btn"
                >
                    Sign In
                </button>

            </form>

            <p class="form-footer">
                Want to apply for a job?

                <a href="index.php?view=signup">
                    Sign Up
                </a>
            </p>

        <?php else: ?>

            <!-- APPLICANT SIGN UP -->

            <form method="POST" action="index.php">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= escape(csrf_token()) ?>"
                >

                <input
                    type="hidden"
                    name="action"
                    value="signup"
                >

                <label for="full_name">
                    Full Name
                </label>

                <input
                    type="text"
                    id="full_name"
                    name="full_name"
                    value="<?= escape($fullName) ?>"
                    maxlength="150"
                    placeholder="Enter full name"
                    required
                >

                <label for="email">
                    Email Address
                </label>

                <input
                    type="email"
                    id="email"
                    name="email"
                    value="<?= escape($email) ?>"
                    placeholder="Enter your email"
                    required
                >

                <!-- AVAILABLE DEPARTMENTS -->

                <label for="applyDepartment">
                    Department
                </label>

                <select
                    id="applyDepartment"
                    <?= !$openings
                        ? 'disabled'
                        : 'required' ?>
                >

                    <option value="">
                        <?= $openings
                            ? 'Select Department'
                            : 'No hiring departments available' ?>
                    </option>

                    <?php foreach (
                        $availableDepartments
                        as $departmentId => $departmentName
                    ): ?>

                        <option
                            value="<?= (int) $departmentId ?>"
                            <?= $selectedDepartment ===
                                (string) $departmentId
                                ? 'selected'
                                : '' ?>
                        >
                            <?= escape($departmentName) ?>
                        </option>

                    <?php endforeach; ?>

                </select>

                <!-- AVAILABLE POSITIONS -->

                <label for="job_opening_id">
                    Position Applying For
                </label>

                <select
                    id="job_opening_id"
                    name="job_opening_id"
                    required
                    disabled
                >

                    <option value="">
                        Select Department First
                    </option>

                    <?php foreach ($openings as $opening): ?>

                        <option
                            value="<?= (int) $opening['id'] ?>"
                            data-dept="<?= (int) $opening['department_id'] ?>"
                        >
                            <?= escape(
                                $opening['position_name']
                            ) ?>
                        </option>

                    <?php endforeach; ?>

                </select>

                <label for="password">
                    Password
                </label>

                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Create a strong password"
                    minlength="12"
                    maxlength="72"
                    required
                >

                <p class="input-note">
                    12-72 characters with uppercase,
                    lowercase, number and symbol.
                </p>

                <label for="confirm_password">
                    Confirm Password
                </label>

                <input
                    type="password"
                    id="confirm_password"
                    name="confirm_password"
                    placeholder="Confirm your password"
                    required
                >

                <button
                    type="submit"
                    class="primary-btn"
                    <?= !$openings ? 'disabled' : '' ?>
                >
                    <?= $openings
                        ? 'Create Applicant Account & Apply'
                        : 'Applications Currently Closed' ?>
                </button>

            </form>

            <p class="form-footer">

                Already have an account?

                <a href="index.php">
                    Sign In
                </a>

            </p>

        <?php endif; ?>

    </section>

</div>

<?php if ($view === 'signup'): ?>

<script>
// ONLY CURRENTLY HIRING POSITIONS
const department =
    document.getElementById('applyDepartment');

const position =
    document.getElementById('job_opening_id');

const openings = Array.from(position.options)
    .filter(option => option.value)
    .map(option => ({
        id: option.value,
        name: option.textContent.trim(),
        department: option.dataset.dept
    }));

function updateAvailablePositions(selected = '') {

    position.replaceChildren();

    const placeholder = new Option(
        department.value
            ? 'Select Available Position'
            : 'Select Department First',
        ''
    );

    position.add(placeholder);

    const matching = openings.filter(
        item => item.department === department.value
    );

    matching.forEach(item => {
        position.add(
            new Option(item.name, item.id)
        );
    });

    if (department.value && matching.length === 0) {
        placeholder.textContent =
            'No Positions Available';
    }

    position.disabled = matching.length === 0;

    if (matching.some(
        item => item.id === String(selected)
    )) {
        position.value = String(selected);
    }
}

department.addEventListener('change', () => {
    updateAvailablePositions();
});

updateAvailablePositions(
    <?= json_encode(
        $selectedOpening,
        JSON_HEX_TAG |
        JSON_HEX_AMP |
        JSON_HEX_APOS |
        JSON_HEX_QUOT
    ) ?>
);
</script>

<?php endif; ?>



</body>

</html>
