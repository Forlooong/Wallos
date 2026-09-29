<?php
require_once WALLOS_ROOT . '/includes/homelab.php';

wallos_test('homelab bootstrap reserves administrator and creates two private identities', function () {
    putenv('HOMELAB_ALLOWED_USERS=zhuqing,yaojia');
    $db = new SQLite3(wallos_test_database());
    $db->enableExceptions(true);
    homelab_bootstrap($db);
    assert_same(HOMELAB_RESERVED_USER, $db->querySingle('SELECT username FROM user WHERE id=1'), 'reserved administrator exists');
    $a = homelab_identity_user($db, 'https://identity.example/auth', 'subject-a', 'zhuqing', ['email' => 'same@example.test']);
    $b = homelab_identity_user($db, 'https://identity.example/auth', 'subject-b', 'yaojia', ['email' => 'same@example.test']);
    assert_true($a['id'] > 1 && $b['id'] > 1 && $a['id'] !== $b['id'], 'both users are distinct ordinary accounts even with same email');
    assert_same('!', $a['password'], 'member password is not a usable hash');
    assert_same('', $a['api_key'], 'API key is not provisioned');
    assert_true($a['main_currency'] !== $b['main_currency'], 'currencies belong to separate members');
    assert_true((int) $db->querySingle('SELECT COUNT(*) FROM categories WHERE user_id=' . $a['id']) > 0, 'upstream defaults provided to member');
    $again = homelab_identity_user($db, 'https://identity.example/auth', 'subject-a', 'zhuqing', ['email' => 'different@example.test']);
    assert_same($a['id'], $again['id'], 'issuer and subject alone select existing identity');
    foreach ([['https://different.example/auth', 'subject-a', 'zhuqing'], ['https://identity.example/auth', 'new-subject', 'zhuqing'], ['https://identity.example/auth', 'subject-a', 'yaojia']] as $conflict) {
        $rejected = false;
        try { homelab_identity_user($db, ...[...$conflict, []]); } catch (RuntimeException $error) { $rejected = true; }
        assert_true($rejected, 'conflicting issuer/subject/name mapping must not merge');
    }
    assert_same(2, (int) $db->querySingle('SELECT COUNT(*) FROM homelab_identity'), 'rejected conflicts leave no partial identity');
    homelab_bootstrap($db);
    assert_same(3, (int) $db->querySingle('SELECT COUNT(*) FROM user'), 'bootstrap is idempotent');
    $db->close();
    putenv('HOMELAB_ALLOWED_USERS');
});

wallos_test('homelab refuses adoption of an existing unrecognized database', function () {
    $db = new SQLite3(wallos_test_database());
    $db->exec("INSERT INTO user (username,email,password,main_currency) VALUES ('existing','','!',1)");
    $rejected = false;
    try { homelab_bootstrap($db); } catch (RuntimeException $error) { $rejected = true; }
    assert_true($rejected, 'existing database cannot be silently mapped');
    assert_same('existing', $db->querySingle('SELECT username FROM user WHERE id=1'), 'original account untouched');
    $db->close();
});

wallos_test('homelab session binds website cookie and identity with fixed expiry', function () {
    $session = ['loggedin' => true, 'userId' => 2, 'homelab_user' => 'zhuqing', 'homelab_cookie_hash' => hash('sha256', 'test-session'), 'homelab_expires' => 300];
    assert_true(homelab_session_matches($session, 'zhuqing', 'test-session', 200), 'matching active website identity accepted');
    assert_true(!homelab_session_matches($session, 'yaojia', 'test-session', 200), 'identity switch rejected');
    assert_true(!homelab_session_matches($session, 'zhuqing', 'replacement', 200), 'website cookie replacement rejected');
    assert_true(!homelab_session_matches($session, 'zhuqing', '', 200), 'website logout rejected');
    assert_true(!homelab_session_matches($session, 'zhuqing', 'test-session', 300), 'absolute expiry rejected');
    $session['userId'] = 1;
    assert_true(!homelab_session_matches($session, 'zhuqing', 'test-session', 200), 'global administrator never accepted');
});

wallos_test('homelab disabled administrative and independent entrypoints fail server policy', function () {
    foreach (['/admin.php', '/endpoints/admin/deleteuser.php', '/endpoints/db/backup.php', '/api/subscriptions/get.php', '/registration.php', '/passwordreset.php', '/totp.php', '/endpoints/user/regenerateapikey.php', '/endpoints/subscription/exportcalendar.php'] as $path) {
        assert_true(homelab_denied_path($path), 'deny ' . $path);
    }
    assert_true(!homelab_denied_path('/endpoints/subscriptions/export.php'), 'authenticated member export remains available');
    assert_true(!homelab_denied_path('/private_file.php'), 'private uploads use authenticated owner handler');
});

wallos_test('homelab deep links remain within the application prefix', function () {
    assert_same('/apps/wallos/stats.php?year=2026', homelab_safe_redirect('/apps/wallos/stats.php?year=2026'), 'valid deep link preserved');
    foreach (['https://evil.test/', '//evil.test/', '/apps/notes/', '/apps/wallos/../admin', '/apps/wallos/%2e%2e/admin', "/apps/wallos/\r\nLocation: bad", '/apps/wallos/%5c/evil', '/apps/wallos/homelab-oidc.php?code=old'] as $path) {
        assert_same('/apps/wallos/', homelab_safe_redirect($path), 'unsafe redirect removed');
    }
});
