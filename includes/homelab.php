<?php
// Shared application policy. The HTTP entry point is homelab_prepend.php.
const HOMELAB_PREFIX = '/apps/wallos/';
const HOMELAB_RESERVED_USER = '__homelab_disabled_admin__';

function homelab_enabled(): bool
{
    return getenv('HOMELAB_ENABLED') === '1';
}

function homelab_env(string $name): string
{
    $value = getenv($name);
    if (!is_string($value) || $value === '') {
        throw new RuntimeException('Missing platform configuration: ' . $name);
    }
    return $value;
}

function homelab_public_url(): string
{
    $value = rtrim(homelab_env('HOMELAB_PUBLIC_URL'), '/');
    $url = parse_url($value);
    if (($url['scheme'] ?? '') !== 'https' || empty($url['host']) ||
        ($url['path'] ?? '') !== rtrim(HOMELAB_PREFIX, '/') ||
        isset($url['user']) || isset($url['pass']) || isset($url['query']) || isset($url['fragment'])) {
        throw new RuntimeException('Invalid platform public URL');
    }
    return $value;
}

function homelab_db(): SQLite3
{
    $db = new SQLite3(__DIR__ . '/../db/wallos.db', SQLITE3_OPEN_READWRITE);
    $db->enableExceptions(true);
    $db->busyTimeout(5000);
    return $db;
}

function homelab_start_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.gc_maxlifetime', '28800');
        session_name('wallos_session');
        session_set_cookie_params([
            'lifetime' => 0, 'path' => HOMELAB_PREFIX,
            'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
        ]);
        session_start();
    }
}

function homelab_forget_session(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
}

function homelab_fail(int $status): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    echo json_encode(['success' => false, 'message' => $status === 503 ? 'Identity service unavailable' : 'Access denied']);
    exit;
}

function homelab_safe_redirect(?string $path): string
{
    if ($path === null || preg_match('/[\\\\\x00-\x20\x7f]/', $path) ||
        !str_starts_with($path, HOMELAB_PREFIX) || str_contains(rawurldecode($path), '..') ||
        str_contains(rawurldecode($path), '\\') || preg_match('/[\r\n]/', rawurldecode($path))) {
        return HOMELAB_PREFIX;
    }
    $parsed = parse_url($path);
    if ($parsed === false || isset($parsed['host']) || isset($parsed['scheme'])) {
        return HOMELAB_PREFIX;
    }
    if (in_array($parsed['path'] ?? '', [HOMELAB_PREFIX . 'login.php', HOMELAB_PREFIX . 'logout.php', HOMELAB_PREFIX . 'homelab-oidc.php'], true)) {
        return HOMELAB_PREFIX;
    }
    return $path;
}

function homelab_site_identity(string $cookie): string
{
    if ($cookie === '' || preg_match('/[\x00-\x20\x7f;,]/', $cookie)) {
        throw new RuntimeException('Website authentication required', 401);
    }
    $authz = homelab_env('HOMELAB_AUTHZ_URL');
    $parsed = parse_url($authz);
    if (($parsed['scheme'] ?? '') !== 'http' || !in_array($parsed['host'] ?? '', ['127.0.0.1', 'localhost', '[::1]'], true)) {
        throw new RuntimeException('Authorization service must use loopback');
    }
    $public = homelab_public_url();
    $host = parse_url($public, PHP_URL_HOST);
    $port = parse_url($public, PHP_URL_PORT);
    $headers = [];
    $curl = curl_init($authz);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 2, CURLOPT_TIMEOUT => 5,
        CURLOPT_HTTPHEADER => [
            'Cookie: site_session=' . $cookie,
            'X-Original-Method: GET', 'X-Original-URL: ' . $public . '/',
            'X-Forwarded-Proto: https', 'X-Forwarded-Host: ' . $host . ($port ? ':' . $port : ''),
        ],
        CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headers): int {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
            return strlen($line);
        },
    ]);
    $result = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    if ($result === false || !in_array($status, [200, 401, 403], true)) {
        throw new RuntimeException('Website identity unavailable', 503);
    }
    $user = $headers['remote-user'] ?? '';
    $groups = array_map('trim', explode(',', $headers['remote-groups'] ?? ''));
    $allowed = array_map('trim', explode(',', homelab_env('HOMELAB_ALLOWED_USERS')));
    if ($status !== 200 || !in_array('site-users', $groups, true) || !in_array($user, $allowed, true)) {
        throw new RuntimeException('Website authorization denied', $status === 401 ? 401 : 403);
    }
    return $user;
}

function homelab_session_matches(array $session, string $websiteUser, string $cookie, int $now): bool
{
    return ($session['loggedin'] ?? false) === true && ($session['userId'] ?? 0) > 1 &&
        ($session['homelab_user'] ?? '') === $websiteUser &&
        $cookie !== '' && isset($session['homelab_cookie_hash']) &&
        hash_equals($session['homelab_cookie_hash'], hash('sha256', $cookie)) &&
        ($session['homelab_expires'] ?? 0) > $now;
}

function homelab_current_user_id(): int
{
    if (empty($GLOBALS['homelab_authenticated']) || empty($_SESSION['userId']) || (int) $_SESSION['userId'] <= 1) {
        homelab_fail(401);
    }
    return (int) $_SESSION['userId'];
}

function homelab_require_user(SQLite3 $db): array
{
    $id = homelab_current_user_id();
    $stmt = $db->prepare('SELECT u.* FROM user u JOIN homelab_identity h ON h.user_id = u.id WHERE u.id = :id AND h.issuer = :issuer AND h.subject = :subject AND h.website_user = :website_user');
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $stmt->bindValue(':issuer', $_SESSION['homelab_issuer'], SQLITE3_TEXT);
    $stmt->bindValue(':subject', $_SESSION['homelab_subject'], SQLITE3_TEXT);
    $stmt->bindValue(':website_user', $_SESSION['homelab_user'], SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        homelab_forget_session();
        homelab_fail(401);
    }
    return $row;
}

function homelab_denied_path(string $path): bool
{
    foreach (['/api/', '/includes/', '/migrations/', '/endpoints/admin/', '/endpoints/db/', '/endpoints/cronjobs/', '/endpoints/ai/', '/endpoints/notifications/'] as $prefix) {
        if (str_starts_with($path, $prefix)) {
            return true;
        }
    }
    return in_array($path, [
        '/admin.php', '/registration.php', '/passwordreset.php', '/totp.php', '/verifyemail.php',
        '/endpoints/user/enable_totp.php', '/endpoints/user/disable_totp.php', '/endpoints/user/regenerateapikey.php',
        '/endpoints/settings/deleteaccount.php', '/endpoints/subscription/exportcalendar.php',
    ], true);
}

function homelab_bootstrap(SQLite3 $db): void
{
    $db->exec('BEGIN IMMEDIATE');
    try {
        $table = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='homelab_identity'");
        if (!$table) {
            if ((int) $db->querySingle('SELECT COUNT(*) FROM user') !== 0) {
                throw new RuntimeException('Refusing to adopt an existing unrecognized Wallos database');
            }
            $stmt = $db->prepare("INSERT INTO user (id, username, email, password, main_currency, avatar, language, budget, firstname, lastname, api_key) VALUES (1, :username, '', '!', 1, 'images/avatars/0.svg', 'zh_cn', 0, '', '', '')");
            $stmt->bindValue(':username', HOMELAB_RESERVED_USER, SQLITE3_TEXT);
            $stmt->execute();
            $db->exec('CREATE TABLE homelab_identity (issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL UNIQUE CHECK(user_id > 1), website_user TEXT NOT NULL UNIQUE, PRIMARY KEY(issuer, subject), FOREIGN KEY(user_id) REFERENCES user(id))');
        }
        $reserved = $db->querySingle('SELECT username FROM user WHERE id=1');
        if ($reserved !== HOMELAB_RESERVED_USER) {
            throw new RuntimeException('Reserved non-login administrator is missing');
        }
        $db->exec("UPDATE admin SET registrations_open=0, login_disabled=0");
        $db->exec('DELETE FROM login_tokens');
        $db->exec('COMMIT');
    } catch (Throwable $error) {
        $db->exec('ROLLBACK');
        throw $error;
    }
}

function homelab_identity_user(SQLite3 $db, string $issuer, string $subject, string $websiteUser, array $claims): array
{
    if ($issuer === '' || $subject === '' || !in_array($websiteUser, array_map('trim', explode(',', homelab_env('HOMELAB_ALLOWED_USERS'))), true)) {
        throw new RuntimeException('Identity is not allowed');
    }
    $db->exec('BEGIN IMMEDIATE');
    try {
        $stmt = $db->prepare('SELECT u.*, h.website_user FROM homelab_identity h JOIN user u ON u.id=h.user_id WHERE h.issuer=:issuer AND h.subject=:subject');
        $stmt->bindValue(':issuer', $issuer, SQLITE3_TEXT);
        $stmt->bindValue(':subject', $subject, SQLITE3_TEXT);
        $user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        if ($user) {
            if ($user['website_user'] !== $websiteUser || (int) $user['id'] <= 1) {
                throw new RuntimeException('Identity mapping changed');
            }
            $db->exec('COMMIT');
            return $user;
        }
        // A pre-existing name is a conflict, never evidence of identity ownership.
        $stmt = $db->prepare('SELECT id FROM user WHERE username=:name');
        $stmt->bindValue(':name', $websiteUser, SQLITE3_TEXT);
        if ($stmt->execute()->fetchArray(SQLITE3_ASSOC)) {
            throw new RuntimeException('Existing account requires an explicit identity mapping');
        }
        $stmt = $db->prepare("INSERT INTO user (username, email, password, main_currency, avatar, language, budget, firstname, lastname, api_key, oidc_sub) VALUES (:username, :email, '!', 1, 'images/avatars/0.svg', 'zh_cn', 0, :firstname, '', '', :subject)");
        $stmt->bindValue(':username', $websiteUser, SQLITE3_TEXT);
        $stmt->bindValue(':email', filter_var($claims['email'] ?? '', FILTER_VALIDATE_EMAIL) ?: '', SQLITE3_TEXT);
        $stmt->bindValue(':firstname', htmlspecialchars($claims['name'] ?? $websiteUser, ENT_QUOTES, 'UTF-8'), SQLITE3_TEXT);
        $stmt->bindValue(':subject', $subject, SQLITE3_TEXT);
        $stmt->execute();
        $id = $db->lastInsertRowID();
        if ($id <= 1) {
            throw new RuntimeException('Reserved administrator must exist before member provisioning');
        }
        $stmt = $db->prepare('INSERT INTO homelab_identity (issuer,subject,user_id,website_user) VALUES (:issuer,:subject,:id,:name)');
        foreach ([':issuer' => $issuer, ':subject' => $subject, ':name' => $websiteUser] as $key => $value) {
            $stmt->bindValue($key, $value, SQLITE3_TEXT);
        }
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();
        $stmt = $db->prepare('INSERT INTO household (name,user_id) VALUES (:name,:id)');
        $stmt->bindValue(':name', $websiteUser, SQLITE3_TEXT);
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();
        // The untouched id=1 seed rows are upstream's defaults, not member data.
        foreach ([
            'categories' => 'name,"order"',
            'payment_methods' => 'name,icon,"order"',
            'currencies' => 'name,symbol,code,rate',
        ] as $table => $columns) {
            $stmt = $db->prepare("INSERT INTO $table ($columns,user_id) SELECT $columns,:id FROM $table WHERE user_id=1");
            $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
            $stmt->execute();
        }
        $stmt = $db->prepare("UPDATE user SET main_currency=(SELECT id FROM currencies WHERE user_id=:id AND code='CNY') WHERE id=:id");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();
        $stmt = $db->prepare("INSERT INTO settings (dark_theme,monthly_price,convert_currency,remove_background,color_theme,hide_disabled,user_id,disabled_to_bottom,show_original_price,mobile_nav,week_starts_sunday) VALUES (2,0,0,0,'blue',0,:id,0,0,0,0)");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();
        require_once __DIR__ . '/default_names.php';
        localize_default_names($db, $id, 'zh_cn');
        $user = $db->querySingle('SELECT * FROM user WHERE id=' . (int) $id, true);
        $db->exec('COMMIT');
        return $user;
    } catch (Throwable $error) {
        $db->exec('ROLLBACK');
        throw $error;
    }
}
