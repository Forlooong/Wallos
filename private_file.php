<?php
require_once __DIR__ . '/includes/homelab.php';
require_once __DIR__ . '/includes/private_uploads.php';

$db = homelab_db();
$userData = homelab_require_user($db);
$file = $_GET['file'] ?? '';
header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD'], true)) {
    http_response_code(405);
    exit;
}
if (!is_string($file) || !wallos_private_upload_owned($db, (int) $userData['id'], $file)) {
    http_response_code(404);
    exit;
}
$root = realpath(__DIR__ . '/images/uploads/logos');
$path = realpath(__DIR__ . '/images/uploads/logos/' . $file);
if (!$root || !$path || !str_starts_with($path, $root . DIRECTORY_SEPARATOR) || !is_file($path)) {
    http_response_code(404);
    exit;
}
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($path);
if (!in_array($mime, ['image/png', 'image/jpeg', 'image/gif', 'image/webp'], true)) {
    http_response_code(404);
    exit;
}
header('Content-Type: ' . $mime);
header('Content-Length: ' . filesize($path));
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    readfile($path);
}
