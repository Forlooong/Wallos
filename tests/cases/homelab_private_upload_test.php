<?php
require_once WALLOS_ROOT . '/includes/private_uploads.php';

wallos_test('homelab_private uploads require the current account reference', function () {
    $db = new SQLite3(':memory:');
    $db->exec('CREATE TABLE subscriptions (user_id INTEGER, logo TEXT, logo_variant TEXT)');
    $db->exec('CREATE TABLE payment_methods (user_id INTEGER, icon TEXT)');
    $db->exec('CREATE TABLE uploaded_avatars (user_id INTEGER, path TEXT)');
    $db->exec("INSERT INTO subscriptions VALUES (2, 'alice.png', 'alice-variant.png'), (3, 'bob.png', NULL)");
    $db->exec("INSERT INTO payment_methods VALUES (2, 'alice-payment.png'), (3, 'bob-payment.png')");
    $db->exec("INSERT INTO uploaded_avatars VALUES (2, 'images/uploads/logos/avatars/alice.png'), (3, 'images/uploads/logos/avatars/bob.png')");

    foreach ([2 => ['alice.png', 'alice-variant.png', 'alice-payment.png', 'avatars/alice.png'],
              3 => ['bob.png', 'bob-payment.png', 'avatars/bob.png']] as $owner => $files) {
        foreach ($files as $file) {
            assert_true(wallos_private_upload_owned($db, $owner, $file), 'owner can read ' . $file);
            assert_true(!wallos_private_upload_owned($db, 5 - $owner, $file), 'other account cannot read ' . $file);
            assert_true(!wallos_private_upload_owned($db, 0, $file), 'anonymous cannot read ' . $file);
        }
    }
    foreach (['missing.png', '../alice.png', 'avatars/../alice.png', '/alice.png', 'alice.png/extra', 'alice.php', 'alice.png%00', 'avatars\\alice.png'] as $file) {
        assert_true(!wallos_private_upload_owned($db, 2, $file), 'invalid or unreferenced file rejected');
    }
    assert_true(wallos_avatar_selectable($db, 2, 'images/avatars/0.svg'), 'built-in avatars are selectable');
    assert_true(wallos_avatar_selectable($db, 2, 'images/uploads/logos/avatars/alice.png'), 'own upload selectable');
    assert_true(!wallos_avatar_selectable($db, 2, 'images/uploads/logos/avatars/bob.png'), 'foreign avatar cannot be assigned to claim ownership');
    assert_true(!wallos_avatar_selectable($db, 2, 'https://example.test/avatar.png'), 'remote avatar is not an authorized upload');
    $db->exec("DELETE FROM subscriptions WHERE logo = 'alice.png'");
    assert_true(!wallos_private_upload_owned($db, 2, 'alice.png'), 'unreferenced upload is no longer readable');
    $db->close();
});
