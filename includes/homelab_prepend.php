<?php
require_once __DIR__ . '/homelab.php';
if (!homelab_enabled() || PHP_SAPI === 'cli') {
    return;
}

// SCRIPT_FILENAME comes from the fixed nginx script mapping, not a client header.
$script = '/' . ltrim(str_replace('\\', '/', substr($_SERVER['SCRIPT_FILENAME'] ?? '', strlen(dirname(__DIR__)))), '/');
header('Cache-Control: no-store, private');
header('Vary: Cookie');
header('X-Content-Type-Options: nosniff');
if ($script === '/health.php') {
    return;
}
if (homelab_denied_path($script)) {
    homelab_fail(403);
}

homelab_start_session();
$public = homelab_public_url();
$origin = substr($public, 0, -strlen(rtrim(HOMELAB_PREFIX, '/')));
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'], true) && ($_SERVER['HTTP_ORIGIN'] ?? '') !== $origin) {
    homelab_fail(403);
}
if ($script === '/login.php' && $method !== 'GET') {
    homelab_fail(403);
}
if ($script === '/endpoints/user/save_user.php' && isset($_POST['password']) && $_POST['password'] !== '') {
    homelab_fail(403);
}

$cookie = $_COOKIE['site_session'] ?? '';
try {
    $websiteUser = homelab_site_identity(is_string($cookie) ? $cookie : '');
} catch (RuntimeException $error) {
    $code = in_array($error->getCode(), [401, 403, 503], true) ? $error->getCode() : 503;
    if ($code !== 503) {
        homelab_forget_session();
    }
    if ($code === 401 && $method === 'GET' && !str_starts_with($script, '/endpoints/') && $script !== '/private_file.php') {
        $return = homelab_safe_redirect($_SERVER['REQUEST_URI'] ?? null);
        header('Location: ' . $origin . '/auth/?rd=' . rawurlencode($origin . $return), true, 302);
        exit;
    }
    homelab_fail($code);
}
$GLOBALS['homelab_website_user'] = $websiteUser;
$GLOBALS['homelab_site_cookie_hash'] = hash('sha256', $cookie);

if ($script === '/homelab-oidc.php') {
    return;
}
if ($script === '/logout.php') {
    // Local application logout never signs out other applications implicitly.
    homelab_forget_session();
    setcookie('wallos_session', '', ['expires' => 1, 'path' => HOMELAB_PREFIX, 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    header('Location: ' . $origin . '/', true, 302);
    exit;
}

if (!homelab_session_matches($_SESSION, $websiteUser, $cookie, time())) {
    $return = homelab_safe_redirect($_SERVER['REQUEST_URI'] ?? null);
    homelab_forget_session();
    if ($method !== 'GET' || str_starts_with($script, '/endpoints/') || $script === '/private_file.php') {
        homelab_fail(401);
    }
    $_SESSION['homelab_return'] = $return;
    header('Location: ' . HOMELAB_PREFIX . 'homelab-oidc.php', true, 302);
    exit;
}
$GLOBALS['homelab_authenticated'] = true;
// The DB mapping is checked for every request, including private-file responses.
$identityDb = homelab_db();
homelab_require_user($identityDb);
$identityDb->close();
if ($script === '/login.php') {
    header('Location: ' . HOMELAB_PREFIX, true, 302);
    exit;
}
