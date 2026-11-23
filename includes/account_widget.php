
<?php
// SHARED ACCOUNT INFORMATION WIDGET
// Displays the logged-in user's account details.
// Automatically adds the profile icon beside
// the existing hamburger icon.

$accountWidgetUser = (
    isset($user) && is_array($user)
)
    ? $user
    : current_user();

if (!$accountWidgetUser) {
    return;
}

$accountWidgetEmployee = null;

// GET LINKED EMPLOYEE INFORMATION
$accountWidgetStmt = $pdo->prepare(
    "SELECT
        e.employee_code,
        e.employment_status,
        e.employment_type,
        e.hire_date,
        d.department_name,
        p.position_name
     FROM employees e
     JOIN departments d
        ON d.id = e.department_id
     JOIN positions p
        ON p.id = e.position_id
     WHERE e.user_id = ?
       AND e.deleted_at IS NULL
     LIMIT 1"
);

$accountWidgetStmt->execute([
    (int) $accountWidgetUser['id']
]);

$accountWidgetEmployee = $accountWidgetStmt->fetch(
    PDO::FETCH_ASSOC
) ?: null;

// FORMAT ROLE NAME
$accountWidgetRole = ucwords(
    str_replace(
        '_',
        ' ',
        $accountWidgetUser['role_name']
    )
);

// FIRST LETTER FOR AVATAR
$accountWidgetInitial = strtoupper(
    substr(
        trim($accountWidgetUser['full_name']),
        0,
        1
    )
);
?>

<style>
/* =====================================
   SIDEBAR TOP BUTTONS
===================================== */

.account-inline-controls {
    display: flex;
    align-items: center;
    gap: 9px;
    margin-bottom: 12px;
}

.account-inline-controls > .toggle-btn {
    margin: 0 !important;
    flex: 0 0 auto;
}

/* ACCOUNT PROFILE ICON */
.account-top-trigger {
    width: 42px;
    height: 42px;
    flex: 0 0 auto;

    display: flex;
    align-items: center;
    justify-content: center;

    border: 1px solid #dbe5dc;
    border-radius: 10px;

    background: #e8efe8;
    color: #526d57;

    font-size: 21px;
    cursor: pointer;

    transition:
        background 0.2s ease,
        transform 0.2s ease;
}

.account-top-trigger:hover {
    background: #d9e8da;
    transform: translateY(-1px);
}

.account-top-trigger:focus-visible {
    outline: 2px solid #526d57;
    outline-offset: 3px;
}

/* =====================================
   COLLAPSED SIDEBAR
===================================== */

/* Keep hamburger visible */
.collapsed .account-inline-controls,
.sidebar.collapsed .account-inline-controls {
    display: flex;
    justify-content: center;
    align-items: center;
}

/* Hide account icon when sidebar collapses */
.collapsed .account-top-trigger,
.sidebar.collapsed .account-top-trigger {
    display: none !important;
}

/* Restore account icon when expanded */
body:not(.collapsed)
.sidebar:not(.collapsed)
.account-top-trigger {
    display: flex;
}

/* =====================================
   ACCOUNT INFORMATION POPUP
===================================== */

.account-info-dialog {
    width: min(460px, 94vw);
    max-height: 88vh;

    overflow-y: auto;

    padding: 25px;

    background: #ffffff;
    color: #26332a;

    border: 1px solid #dbe5dc;
    border-radius: 18px;

    box-shadow:
        0 20px 55px rgba(38, 51, 42, 0.20);
}

.account-info-dialog::backdrop {
    background: rgba(20, 32, 24, 0.55);
}

.account-info-dialog h2 {
    font-size: 24px;
    margin: 0 0 18px;
}

/* =====================================
   PROFILE HEADER
===================================== */

.account-info-heading {
    display: flex;
    align-items: center;

    gap: 13px;
    margin-bottom: 18px;
}

.account-info-avatar {
    width: 58px;
    height: 58px;

    flex: none;

    border-radius: 50%;
    background: #718b75;
    color: white;

    display: flex;
    align-items: center;
    justify-content: center;

    font-size: 26px;
    font-weight: 800;
}

.account-info-person {
    min-width: 0;
}

.account-info-person strong {
    display: block;

    font-size: 18px;
    overflow-wrap: anywhere;
}

.account-info-person span {
    display: block;

    margin-top: 4px;

    color: #526d57;
    font-size: 14px;
}

/* =====================================
   ACCOUNT DETAIL ROWS
===================================== */

.account-info-row {
    padding: 11px 0;
    border-top: 1px solid #e3e9e1;
}

.account-info-row span {
    display: block;

    font-size: 13px;
    color: #788078;

    margin-bottom: 5px;
}

.account-info-row strong {
    display: block;

    font-size: 15px;
    overflow-wrap: anywhere;
}

.account-info-hint {
    color: #788078;

    font-size: 13px;
    line-height: 1.6;
}

/* =====================================
   CLOSE BUTTON
===================================== */

.account-info-close {
    display: block;

    margin: 20px 0 0 auto;

    border: none;
    border-radius: 9px;

    padding: 11px 20px;

    background: #718b75;
    color: white;

    font: inherit;
    font-weight: 700;

    cursor: pointer;
}

.account-info-close:hover {
    background: #526d57;
}

/* =====================================
   MOBILE
===================================== */

@media (max-width: 600px) {
    .account-info-dialog {
        padding: 19px;
    }

    .account-info-dialog h2 {
        font-size: 21px;
    }

    .account-info-avatar {
        width: 50px;
        height: 50px;
        font-size: 23px;
    }
}
</style>

<!-- =====================================
     ACCOUNT INFORMATION POPUP
===================================== -->

<dialog
    class="account-info-dialog"
    id="accountInfoDialog"
    aria-labelledby="accountInfoTitle"
>

    <h2 id="accountInfoTitle">
        My Account Information
    </h2>

    <!-- PROFILE HEADER -->
    <div class="account-info-heading">

        <div class="account-info-avatar">
            <?= escape(
                $accountWidgetInitial
            ) ?>
        </div>

        <div class="account-info-person">

            <strong>
                <?= escape(
                    $accountWidgetUser['full_name']
                ) ?>
            </strong>

            <span>
                <?= escape(
                    $accountWidgetRole
                ) ?>
            </span>

        </div>
    </div>

    <!-- FULL NAME -->
    <div class="account-info-row">

        <span>Full Name</span>

        <strong>
            <?= escape(
                $accountWidgetUser['full_name']
            ) ?>
        </strong>

    </div>

    <!-- EMAIL ADDRESS -->
    <div class="account-info-row">

        <span>Email Address</span>

        <strong>
            <?= escape(
                $accountWidgetUser['email']
            ) ?>
        </strong>

    </div>

    <!-- LOGIN ROLE -->
    <div class="account-info-row">

        <span>Login Role</span>

        <strong>
            <?= escape(
                $accountWidgetRole
            ) ?>
        </strong>

    </div>

    <!-- LINKED EMPLOYEE INFORMATION -->
    <?php if ($accountWidgetEmployee): ?>

        <!-- EMPLOYEE CODE -->
        <div class="account-info-row">

            <span>Employee ID</span>

            <strong>
                <?= escape(
                    $accountWidgetEmployee['employee_code']
                ) ?>
            </strong>

        </div>

        <!-- DEPARTMENT -->
        <div class="account-info-row">

            <span>Department</span>

            <strong>
                <?= escape(
                    $accountWidgetEmployee['department_name']
                ) ?>
            </strong>

        </div>

        <!-- POSITION -->
        <div class="account-info-row">

            <span>Position</span>

            <strong>
                <?= escape(
                    $accountWidgetEmployee['position_name']
                ) ?>
            </strong>

        </div>

        <!-- EMPLOYMENT TYPE -->
        <div class="account-info-row">

            <span>Employment Type</span>

            <strong>
                <?= escape(
                    $accountWidgetEmployee['employment_type']
                ) ?>
            </strong>

        </div>

        <!-- EMPLOYMENT STATUS -->
        <div class="account-info-row">

            <span>Employment Status</span>

            <strong>
                <?= escape(
                    $accountWidgetEmployee['employment_status']
                ) ?>
            </strong>

        </div>

        <!-- HIRE DATE -->
        <div class="account-info-row">

            <span>Hire Date</span>

            <strong>
                <?= !empty(
                    $accountWidgetEmployee['hire_date']
                )
                    ? escape(
                        date(
                            'F d, Y',
                            strtotime(
                                $accountWidgetEmployee['hire_date']
                            )
                        )
                    )
                    : 'Not available' ?>
            </strong>

        </div>

    <?php elseif (
        $accountWidgetUser['role_name'] !== 'applicant'
    ): ?>

        <p class="account-info-hint">
            No employee record is currently
            linked to this login account.
        </p>

    <?php endif; ?>

    <p class="account-info-hint">
        Your account information is read-only.
        Passwords are never displayed.
    </p>

    <!-- CLOSE -->
    <form method="dialog">

        <button
            type="submit"
            class="account-info-close"
        >
            Close
        </button>

    </form>

</dialog>

<!-- =====================================
     ACCOUNT BUTTON SCRIPT
===================================== -->

<script>
(function () {

    // FIND EXISTING HAMBURGER BUTTON
    const burger = document.getElementById(
        'sidebarToggle'
    );

    // FIND ACCOUNT POPUP
    const dialog = document.getElementById(
        'accountInfoDialog'
    );

    if (
        !burger ||
        !dialog ||
        !burger.parentElement
    ) {
        return;
    }

    // PREVENT DUPLICATE ACCOUNT BUTTON
    if (
        document.getElementById(
            'accountInfoTrigger'
        )
    ) {
        return;
    }

    // GROUP BURGER + ACCOUNT ICON
    const controls = document.createElement(
        'div'
    );

    controls.className =
        'account-inline-controls';

    burger.parentElement.insertBefore(
        controls,
        burger
    );

    controls.appendChild(burger);

    // CREATE ACCOUNT BUTTON
    const profileButton = document.createElement(
        'button'
    );

    profileButton.type = 'button';

    profileButton.id =
        'accountInfoTrigger';

    profileButton.className =
        'account-top-trigger';

    profileButton.textContent = '👤';

    profileButton.title =
        'My Account Information';

    profileButton.setAttribute(
        'aria-label',
        'View My Account Information'
    );

    // OPEN ACCOUNT INFO
    profileButton.addEventListener(
        'click',
        function () {
            dialog.showModal();
        }
    );

    controls.appendChild(profileButton);

})();
</script>
