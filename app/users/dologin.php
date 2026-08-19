<?php
/*
 *******************************************************************************
 * daloRADIUS - RADIUS Web Platform
 * Copyright (C) 2007 - Liran Tal <liran@lirantal.com> All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *******************************************************************************
 *
 * Description:    logs in users by validating credentials and checking
 *                 authorization in the database
 *
 * Authors:        Liran Tal <liran@lirantal.com>
 *
 *
 *******************************************************************************
 *
 * Enable User Portal login
 *
 *******************************************************************************
 */

    include_once implode(DIRECTORY_SEPARATOR, [ __DIR__, '..', 'common', 'includes', 'config_read.php' ]);
    include implode(DIRECTORY_SEPARATOR, [ __DIR__, 'library', 'sessions.php' ]);

    dalo_session_start();

    $authenticated = false;

    if ($_SERVER['REQUEST_METHOD'] === 'POST'
        && isset($_POST['csrf_token']) && dalo_check_csrf_token($_POST['csrf_token'])
        && isset($_POST['login_user']) && isset($_POST['login_pass'])) {

        $login_user = trim($_POST['login_user']);
        $login_pass = trim($_POST['login_pass']);

        if (!empty($login_user) && !empty($login_pass)) {
            include implode(DIRECTORY_SEPARATOR, [ __DIR__, '..', 'common', 'includes', 'db_open.php' ]);

            $sql = sprintf("SELECT username, portalloginpassword FROM %s WHERE username=?",
                           $configValues['CONFIG_DB_TBL_DALOUSERINFO']);
            $stmt = $dbSocket->prepare($sql);
            $res = $dbSocket->execute($stmt, [ $login_user ]);
            $dbSocket->freePrepared($stmt);

            if (!DB::isError($res) && $res->numRows() === 1) {
                $row = $res->fetchRow(DB_FETCHMODE_ASSOC);
                $stored_password = isset($row['portalloginpassword']) ? $row['portalloginpassword'] : '';
                $verified = (!empty($stored_password) && password_verify($login_pass, $stored_password));
                $legacy_verified = (!$verified && !empty($stored_password) && hash_equals($stored_password, $login_pass));

                if ($verified || $legacy_verified) {
                    if ($legacy_verified || ($verified && password_needs_rehash($stored_password, PASSWORD_DEFAULT))) {
                        $sql = sprintf("UPDATE %s SET portalloginpassword=? WHERE username=?",
                                       $configValues['CONFIG_DB_TBL_DALOUSERINFO']);
                        $stmt = $dbSocket->prepare($sql);
                        $res = $dbSocket->execute($stmt, [ password_hash($login_pass, PASSWORD_DEFAULT), $login_user ]);
                        $dbSocket->freePrepared($stmt);
                    }

                    session_regenerate_id(true);
                    $_SESSION['logged_in'] = true;
                    $_SESSION['login_user'] = $login_user;
                    unset($_SESSION['login_error']);
                    $authenticated = true;
                }
            }

            include implode(DIRECTORY_SEPARATOR, [ __DIR__, '..', 'common', 'includes', 'db_close.php' ]);
        }

        if ($authenticated) {
            header('Location: index.php');
            exit;
        }

        $_SESSION['logged_in'] = false;
        unset($_SESSION['login_user']);
        $_SESSION['login_error'] = true;
        header('Location: login.php');
        exit;
    }
    header('Location: login.php');
    header('Location: login.php');
    exit;

?>
