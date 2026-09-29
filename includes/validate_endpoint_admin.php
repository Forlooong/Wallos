<?php
if (getenv('HOMELAB_ENABLED') === '1') {
    http_response_code(403);
    exit;
}
require_once __DIR__ . '/validate_endpoint.php';
// Check that user is an admin
if ($userId !== 1) {
    die(json_encode([
        "success" => false,
        "message" => translate('error', $i18n)
    ]));
}
