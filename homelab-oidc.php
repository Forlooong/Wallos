<?php
require_once __DIR__ . '/includes/homelab.php';
if (!homelab_enabled() || empty($GLOBALS['homelab_website_user']) || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    homelab_fail(403);
}
require_once __DIR__ . '/vendor/autoload.php';

try {
    $issuer = rtrim(homelab_env('HOMELAB_OIDC_ISSUER'), '/');
    if (parse_url($issuer, PHP_URL_SCHEME) !== 'https') {
        throw new RuntimeException('OIDC issuer must use HTTPS');
    }
    $secret = trim(file_get_contents(homelab_env('HOMELAB_OIDC_CLIENT_SECRET_FILE')));
    if ($secret === '') {
        throw new RuntimeException('OIDC client secret is missing');
    }
    $oidc = new Jumbojett\OpenIDConnectClient($issuer, homelab_env('HOMELAB_OIDC_CLIENT_ID'), $secret);
    $oidc->setRedirectURL(homelab_public_url() . '/homelab-oidc.php');
    $oidc->setIssuer($issuer);
    $oidc->setIssuerValidator(static fn(string $actual): bool => hash_equals($issuer, $actual));
    $oidc->setAllowImplicitFlow(false);
    $oidc->setCodeChallengeMethod('S256');
    $oidc->addScope(['openid', 'profile', 'email']);
    $oidc->setTimeout(5);
    if (getenv('HOMELAB_OIDC_CA_FILE')) {
        $oidc->setCertPath(homelab_env('HOMELAB_OIDC_CA_FILE'));
    }

    $callback = isset($_GET['code']) || isset($_GET['error']);
    if (!$callback) {
        $_SESSION['homelab_oidc_site_user'] = $GLOBALS['homelab_website_user'];
        $_SESSION['homelab_oidc_cookie_hash'] = $GLOBALS['homelab_site_cookie_hash'];
        $_SESSION['homelab_oidc_started'] = time();
    } elseif (($_SESSION['homelab_oidc_site_user'] ?? '') !== $GLOBALS['homelab_website_user'] ||
        !hash_equals($_SESSION['homelab_oidc_cookie_hash'] ?? '', $GLOBALS['homelab_site_cookie_hash']) ||
        ($_SESSION['homelab_oidc_started'] ?? 0) < time() - 300) {
        throw new RuntimeException('Website identity changed during sign-in');
    }
    if ($callback && (!is_string($_GET['code'] ?? null) || $_GET['code'] === '' ||
        !is_string($_GET['state'] ?? null) || !is_string($_SESSION['openid_connect_state'] ?? null) ||
        !hash_equals($_SESSION['openid_connect_state'], $_GET['state']))) {
        throw new RuntimeException('Invalid authorization response');
    }

    $expectedNonce = $_SESSION['openid_connect_nonce'] ?? '';
    // The maintained library validates signatures and claims; the application also
    // requires nonce/time claims that the general-purpose library treats as optional.
    if (!$oidc->authenticate()) {
        throw new RuntimeException('OIDC authentication failed');
    }
    $verified = $oidc->getVerifiedClaims();
    $profile = $oidc->requestUserInfo();
    if (!is_object($verified) || !is_object($profile) || empty($verified->sub) ||
        ($oidc->getIdTokenHeader()->alg ?? '') !== 'RS256' ||
        !is_string($expectedNonce) || $expectedNonce === '' ||
        !is_string($verified->nonce ?? null) || !hash_equals($expectedNonce, $verified->nonce) ||
        !is_int($verified->exp ?? null) || $verified->exp <= time() ||
        !is_int($verified->iat ?? null) || $verified->iat > time() + 30 ||
        (isset($verified->azp) && $verified->azp !== homelab_env('HOMELAB_OIDC_CLIENT_ID')) ||
        (is_array($verified->aud) && count($verified->aud) > 1 && !isset($verified->azp)) ||
        !hash_equals((string) $verified->sub, (string) ($profile->sub ?? '')) ||
        ($profile->preferred_username ?? '') !== $GLOBALS['homelab_website_user']) {
        throw new RuntimeException('OIDC and website identities do not match');
    }
    $db = homelab_db();
    $user = homelab_identity_user($db, $issuer, (string) $verified->sub, $GLOBALS['homelab_website_user'], (array) $profile);
    $db->close();
    $return = homelab_safe_redirect($_SESSION['homelab_return'] ?? null);
    homelab_forget_session();
    $_SESSION = [
        'loggedin' => true, 'userId' => (int) $user['id'], 'username' => $user['username'],
        'main_currency' => $user['main_currency'], 'from_oidc' => true,
        'homelab_issuer' => $issuer, 'homelab_subject' => (string) $verified->sub,
        'homelab_user' => $GLOBALS['homelab_website_user'],
        'homelab_cookie_hash' => $GLOBALS['homelab_site_cookie_hash'],
        'homelab_expires' => time() + 28800,
    ];
    setcookie('language', $user['language'], ['path' => HOMELAB_PREFIX, 'secure' => true, 'samesite' => 'Lax']);
    header('Location: ' . $return, true, 302);
    exit;
} catch (Throwable $error) {
    // Never log provider responses, authorization codes, cookies, tokens or secrets.
    homelab_forget_session();
    error_log('Wallos platform sign-in rejected (' . get_class($error) . ')');
    homelab_fail(401);
}
