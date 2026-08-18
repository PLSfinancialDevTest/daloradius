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

    include('../common/includes/main_vars.php');
    include('../common/includes/db_open.php');

    if (isset($_POST['login_user']) && isset($_POST['login_pass'])) {
        $login_user = isset($_POST['login_user']) ? trim($_POST['login_user']) : '';
        $login_pass = isset($_POST['login_pass']) ? trim($_POST['login_pass']) : '';

        if (empty($login_user) || empty($login_pass)) {
            header('Location: login-portal.php?error=1');
            exit;
        }

        $sql_WHERE = [];
        $sql_WHERE[] = sprintf("portalloginpassword='%s'", $dbSocket->escapeSimple($login_pass));
        $sql_WHERE[] = sprintf("username='%s'", $dbSocket->escapeSimple($login_user));

        $sql = sprintf("SELECT COUNT(id) FROM %s WHERE ", $configValues['CONFIG_DB_TBL_DALOUSERINFO'])
             . implode(" AND ", $sql_WHERE);

        $res = $dbSocket->query($sql);
        $numrows = intval($res->fetchrow()[0]);

        // we only accept ONE AND ONLY ONE RECORD as result
        if ($numrows === 1) {
            // Regenerate session ID to prevent session fixation attacks
            session_regenerate_id(true);
            $_SESSION['logged_in'] = true;
            $_SESSION['login_user'] = $login_user;
        }

        include('../common/includes/db_close.php');

        if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
            header('Location: index-portal.php');
            exit;
        } else {
            header('Location: login-portal.php?error=1');
            exit;
        }
    }

    include('../common/includes/db_close.php');
    header('Location: login-portal.php');
    exit;

?>
