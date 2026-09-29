<?php
require_once __DIR__ . '/homelab.php';
if (PHP_SAPI !== 'cli' || !homelab_enabled()) {
    exit(1);
}
homelab_bootstrap(homelab_db());
echo "Platform identity boundary initialized.\n";
