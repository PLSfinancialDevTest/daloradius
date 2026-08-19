<?php
/*
 * Kerberos SSO integration for daloRADIUS operators.
 *
 * Apache mod_auth_gssapi authenticates the directory user and exposes REMOTE_USER.
 *
 * This helper maps REMOTE_USER to daloRADIUS operators.username,
 * looks up operators.id, and populates the daloRADIUS session values
 * required by check_operator_perm.php.
 */

if (
    array_key_exists('REMOTE_USER', $_SERVER)
    && $_SERVER['REMOTE_USER'] !== ''
) {
    $operatorUser = strtolower($_SERVER['REMOTE_USER']);

    // Strip Kerberos realm if present, example: user@EXAMPLE.COM
    $operatorUser = preg_replace('/@.*$/', '', $operatorUser);

    // Strip configured Windows domain prefix if present, example: EXAMPLE\user
    $configuredDomain = (isset($configValues['CONFIG_SSO_WINDOWS_DOMAIN']) && !empty(trim($configValues['CONFIG_SSO_WINDOWS_DOMAIN'])))
                      ? trim($configValues['CONFIG_SSO_WINDOWS_DOMAIN'])
                      : '';
    if ($configuredDomain !== '') {
        $operatorUser = preg_replace('/^' . preg_quote($configuredDomain, '/') . '\\\\/i', '', $operatorUser);
    }

    if ($operatorUser === '') {
        return;
    }

    $currentSessionOperatorUser = (isset($_SESSION['operator_user'])) ? strtolower(trim($_SESSION['operator_user'])) : '';
    $currentSessionOperatorId = (isset($_SESSION['operator_id'])) ? intval($_SESSION['operator_id']) : 0;
    $isCurrentSessionAlreadyMapped = (
        array_key_exists('daloradius_logged_in', $_SESSION)
        && $_SESSION['daloradius_logged_in'] === true
        && $currentSessionOperatorId > 0
        && $currentSessionOperatorUser === $operatorUser
    );

    if ($isCurrentSessionAlreadyMapped) {
        return;
    }

    include(implode(DIRECTORY_SEPARATOR, [ __DIR__, '..', '..', 'common', 'includes', 'db_open.php' ]));

    $sql = sprintf(
        "SELECT id FROM %s WHERE username='%s' LIMIT 1",
        $configValues['CONFIG_DB_TBL_DALOOPERATORS'],
        $dbSocket->escapeSimple($operatorUser)
    );

    $operatorIdResult = $dbSocket->getOne($sql);
    if (DB::isError($operatorIdResult)) {
        include(implode(DIRECTORY_SEPARATOR, [ __DIR__, '..', '..', 'common', 'includes', 'db_close.php' ]));
        return;
    }

    $operatorId = intval($operatorIdResult);

    include(implode(DIRECTORY_SEPARATOR, [ __DIR__, '..', '..', 'common', 'includes', 'db_close.php' ]));

    if ($operatorId > 0) {
        // Regenerate session ID to prevent session fixation attacks
        session_regenerate_id(true);
        
        $_SESSION['daloradius_logged_in'] = true;
        $_SESSION['operator_id'] = $operatorId;
        $_SESSION['operator_user'] = $operatorUser;
        $_SESSION['operator_name'] = $operatorUser;
        $_SESSION['operator_login_time'] = time();
        $_SESSION['location_name'] = 'default';
        $_SESSION['location'] = 'default';
        
        // Audit log: SSO login with original REMOTE_USER for traceability
    } else {
        $_SESSION['daloradius_logged_in'] = false;
        unset($_SESSION['operator_id'], $_SESSION['operator_user'], $_SESSION['operator_name'], $_SESSION['operator_login_time']);
    }
}
