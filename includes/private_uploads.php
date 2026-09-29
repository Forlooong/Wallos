<?php

/** Authorization follows database references; filenames never grant ownership. */
function wallos_private_upload_owned(SQLite3 $db, int $userId, string $file): bool
{
    if ($userId <= 0 || !preg_match('/\A(?:avatars\/)?[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:png|jpe?g|gif|webp)\z/i', $file)) {
        return false;
    }

    if (str_starts_with($file, 'avatars/')) {
        $query = $db->prepare('SELECT 1 FROM uploaded_avatars WHERE user_id = :user AND path = :file LIMIT 1');
        $query->bindValue(':file', 'images/uploads/logos/' . $file, SQLITE3_TEXT);
    } else {
        $query = $db->prepare('SELECT 1 FROM subscriptions WHERE user_id = :user AND (logo = :file OR logo_variant = :file)
                              UNION ALL SELECT 1 FROM payment_methods WHERE user_id = :user AND icon = :file LIMIT 1');
        $query->bindValue(':file', $file, SQLITE3_TEXT);
    }
    $query->bindValue(':user', $userId, SQLITE3_INTEGER);
    return $query->execute()->fetchArray(SQLITE3_NUM) !== false;
}

function wallos_avatar_selectable(SQLite3 $db, int $userId, string $avatar): bool
{
    if (preg_match('/\Aimages\/avatars\/[0-9]\.svg\z/', $avatar)) {
        return true;
    }
    $prefix = 'images/uploads/logos/';
    return str_starts_with($avatar, $prefix)
        && wallos_private_upload_owned($db, $userId, substr($avatar, strlen($prefix)));
}
