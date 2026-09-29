<?php
header('Content-Type: application/json');
header('Cache-Control: no-store');
if (!is_file('/tmp/wallos-ready') || !is_file(__DIR__ . '/db/wallos.db')) {
    http_response_code(503);
    echo json_encode(['status' => 'starting']);
    exit;
}
try {
    $healthDb = new SQLite3(__DIR__ . '/db/wallos.db', SQLITE3_OPEN_READONLY);
    $ready = (int) $healthDb->querySingle('SELECT COUNT(*) FROM user WHERE id = 1') === 1;
    $healthDb->close();
    http_response_code($ready ? 200 : 503);
    echo json_encode(['status' => $ready ? 'ok' : 'starting']);
} catch (Throwable $error) {
    http_response_code(503);
    echo json_encode(['status' => 'unavailable']);
}
