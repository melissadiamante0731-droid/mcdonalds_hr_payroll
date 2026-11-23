<?php
declare(strict_types=1);

require_once __DIR__ . "/../config/db.php";

if (session_status() === PHP_SESSION_NONE) {
    session_name("mcd_spb_session");

    session_set_cookie_params([
        "lifetime" => 0,
        "path" => "/mcdonalds_hr_payroll/",
        "secure" => !empty($_SERVER["HTTPS"])
                    && $_SERVER["HTTPS"] !== "off",
        "httponly" => true,
        "samesite" => "Lax"
    ]);

    session_start();
}

function escape($value): string {
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        "UTF-8"
    );
}

function csrf_token(): string {
    if (empty($_SESSION["csrf_token"])) {
        $_SESSION["csrf_token"] =
            bin2hex(random_bytes(32));
    }

    return $_SESSION["csrf_token"];
}

function valid_csrf(): bool {
    return hash_equals(
        csrf_token(),
        (string) ($_POST["csrf_token"] ?? "")
    );
}

function current_user(): ?array {
    global $pdo;

    $id = (int) ($_SESSION["user_id"] ?? 0);

    if ($id <= 0) {
        return null;
    }

    $stmt = $pdo->prepare(
        "SELECT u.id, u.full_name, u.email,
                r.role_name
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
         WHERE u.id = ? AND u.is_active = 1
         LIMIT 1"
    );

    $stmt->execute([$id]);
    $user = $stmt->fetch();

    if (!$user) {
        unset($_SESSION["user_id"]);
        return null;
    }

    return $user;
}

function require_login(): array {
    $user = current_user();

    if (!$user) {
        header("Location: index.php");
        exit;
    }

    return $user;
}

function sign_in(int $userId): void {
    session_regenerate_id(true);

    $_SESSION["user_id"] = $userId;
    $_SESSION["csrf_token"] =
        bin2hex(random_bytes(32));
}
?>
