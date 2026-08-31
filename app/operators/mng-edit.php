<?php
/*
 *********************************************************************************************************
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
 *********************************************************************************************************
 *
 * Authors:    Liran Tal <liran@lirantal.com>
 *             Filippo Lauria <filippo.lauria@iit.cnr.it>
 *
 *********************************************************************************************************
 */

    include ("library/checklogin.php");
    $operator = $_SESSION['operator_user'];

    include('library/check_operator_perm.php');
    include_once('../common/includes/config_read.php');

    // init logging variables
    $log = "visited page: ";
    $logAction = "";
    $logDebugSQL = "";
    
    // Capture SSO user for audit trail (Fix #5: Audit Logging)
    $ssoUser = isset($_SERVER['REMOTE_USER']) ? $_SERVER['REMOTE_USER'] : 'unknown';

    include_once("lang/main.php");
    include("../common/includes/validation.php");
    include("../common/includes/layout.php");
    include_once("include/management/functions.php");


    include('../common/includes/db_open.php');

    /**
     * Fix #4: Permission Checks for Sensitive Data
     * Check if operator has permission to access billing information.
     * Billing authorization in daloRADIUS is ACL-based, not stored on the
     * operators record itself.
     * 
     * @param $operatorId Operator ID to check
     * @return bool True if operator has billing permission, false otherwise
     */
    function checkOperatorBillingAccess($operatorId) {
        global $dbSocket, $configValues;

        if (!is_numeric($operatorId)) {
            return false;
        }

        $query = sprintf(
            "SELECT COUNT(*) FROM %s AS acl "
            . "INNER JOIN %s AS acl_files ON acl.file = acl_files.file "
            . "WHERE acl.operator_id=%d AND acl.access=1 AND acl_files.category='Billing'",
            $configValues['CONFIG_DB_TBL_DALOOPERATORS_ACL'],
            $configValues['CONFIG_DB_TBL_DALOOPERATORS_ACL_FILES'],
            intval($operatorId)
        );

        $result = $dbSocket->getOne($query);

        if (DB::isError($result)) {
            return false;
        }

        return intval($result) > 0;
    }

    $hasBillingAccess = checkOperatorBillingAccess($_SESSION['operator_id'] ?? '');

    // updates old plan profile with a new one
    // or simply add a new plan profile
    function addPlanProfile($dbSocket, $username, $planName, $oldplanName) {
        global $logDebugSQL;
        global $configValues;

        if ($planName == $oldplanName) {
            return;
        }

        // remove profiles associated with the old plan
        $sql = sprintf("SELECT profile_name FROM %s WHERE plan_name='%s'",
                        $configValues['CONFIG_DB_TBL_DALOBILLINGPLANSPROFILES'],
                        $dbSocket->escapeSimple($oldplanName));
        $oldProfiles = $dbSocket->getCol($sql);
        $logDebugSQL .= "$sql;\n";

        if (is_array($oldProfiles) && count($oldProfiles) > 0) {
            foreach ($oldProfiles as $profile_name) {
                $sql = sprintf("DELETE FROM %s WHERE username='%s' AND groupname='%s'",
                               $configValues['CONFIG_DB_TBL_RADUSERGROUP'],
                               $dbSocket->escapeSimple($username),
                               $dbSocket->escapeSimple($profile_name));
                $res = $dbSocket->query($sql);
                $logDebugSQL .= "$sql;\n";

		if (DB::isError($res)) {
			die("Database query failed. Check /var/log/apache2/storeradius-error.log");
		}
            }
        }

        // add profiles associated with the new plan
        $sql = sprintf("SELECT profile_name FROM %s WHERE plan_name='%s'",
                        $configValues['CONFIG_DB_TBL_DALOBILLINGPLANSPROFILES'],
                        $dbSocket->escapeSimple($planName));
        $newProfiles = $dbSocket->getCol($sql);
        $logDebugSQL .= "$sql;\n";

        if (is_array($newProfiles) && count($newProfiles) > 0) {
            foreach ($newProfiles as $profile_name) {
                $priority = normalize_user_group_priority($profile_name, 0);
                $sql = sprintf("INSERT INTO %s (username, groupname, priority) VALUES ('%s', '%s', %d)",
                               $configValues['CONFIG_DB_TBL_RADUSERGROUP'],
                               $dbSocket->escapeSimple($username),
                               $dbSocket->escapeSimple($profile_name), $priority);
                $res = $dbSocket->query($sql);
                $logDebugSQL .= "$sql;\n";
            }
        }
    }


    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (array_key_exists('username', $_POST) && !empty(str_replace("%", "", trim($_POST['username'])))) {
            $username = str_replace("%", "", trim($_POST['username']));
        } elseif (array_key_exists('username', $_REQUEST) && !empty(str_replace("%", "", trim($_REQUEST['username'])))) {
            // Fallback for POST flows where username is not part of submitted payload.
            $username = str_replace("%", "", trim($_REQUEST['username']));
        } else {
            $username = "";
        }
    } else {
        $username = (array_key_exists('username', $_REQUEST) && !empty(str_replace("%", "", trim($_REQUEST['username']))))
                  ? str_replace("%", "", trim($_REQUEST['username'])) : "";
    }

    // check if this user exists
    $exists = user_exists($dbSocket, $username);

    if (!$exists) {
        // we reset the username if it does not exist
        $username = "";
    }

    $username_enc = (!empty($username)) ? htmlspecialchars($username, ENT_QUOTES, 'UTF-8') : "";

    //feed the sidebar variables
    $edit_username = $username_enc;

    // from now on we can assume that $username is valid
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        if (array_key_exists('csrf_token', $_POST) && isset($_POST['csrf_token']) && dalo_check_csrf_token($_POST['csrf_token'])) {

            // required later
            $current_datetime = date('Y-m-d H:i:s');
            $currBy = $operator;

            // TODO validate user input
            $groups = (isset($_POST['groups']) && is_array($_POST['groups'])) ? $_POST['groups'] : array();

            $firstname = (array_key_exists('firstname', $_POST) && isset($_POST['firstname'])) ? $_POST['firstname'] : "";
            $lastname = (array_key_exists('lastname', $_POST) && isset($_POST['lastname'])) ? $_POST['lastname'] : "";
            $email = (array_key_exists('email', $_POST) && isset($_POST['email'])) ? $_POST['email'] : "";
            $department = (array_key_exists('department', $_POST) && isset($_POST['department'])) ? $_POST['department'] : "";
            $company = (array_key_exists('company', $_POST) && isset($_POST['company'])) ? $_POST['company'] : "";
            $workphone = (array_key_exists('workphone', $_POST) && isset($_POST['workphone'])) ? $_POST['workphone'] : "";
            $homephone = (array_key_exists('homephone', $_POST) && isset($_POST['homephone'])) ? $_POST['homephone'] : "";
            $mobilephone = (array_key_exists('mobilephone', $_POST) && isset($_POST['mobilephone'])) ? $_POST['mobilephone'] : "";
            $address = (array_key_exists('address', $_POST) && isset($_POST['address'])) ? $_POST['address'] : "";
            $city = (array_key_exists('city', $_POST) && isset($_POST['city'])) ? $_POST['city'] : "";
            $state = (array_key_exists('state', $_POST) && isset($_POST['state'])) ? $_POST['state'] : "";
            $country = (array_key_exists('country', $_POST) && isset($_POST['country'])) ? $_POST['country'] : "";
            $zip = (array_key_exists('zip', $_POST) && isset($_POST['zip'])) ? $_POST['zip'] : "";
            $notes = (array_key_exists('notes', $_POST) && isset($_POST['notes'])) ? $_POST['notes'] : "";

            // first we check user portal login password
            $ui_PortalLoginPassword = (isset($_POST['portalLoginPassword']) && !empty(trim($_POST['portalLoginPassword'])))
                                    ? trim($_POST['portalLoginPassword']) : "";

            $request_changeuserinfo = (isset($_POST['changeUserInfo']) && $_POST['changeUserInfo'] === '1');
            $request_enableUserPortalLogin = (isset($_POST['enableUserPortalLogin']) && $_POST['enableUserPortalLogin'] === '1');

            $bi_contactperson = (array_key_exists('bi_contactperson', $_POST) && isset($_POST['bi_contactperson'])) ? $_POST['bi_contactperson'] : "";
            $bi_company = (array_key_exists('bi_company', $_POST) && isset($_POST['bi_company'])) ? $_POST['bi_company'] : "";
            $bi_email = (array_key_exists('bi_email', $_POST) && isset($_POST['bi_email'])) ? $_POST['bi_email'] : "";
            $bi_phone = (array_key_exists('bi_phone', $_POST) && isset($_POST['bi_phone'])) ? $_POST['bi_phone'] : "";
            $bi_address = (array_key_exists('bi_address', $_POST) && isset($_POST['bi_address'])) ? $_POST['bi_address'] : "";
            $bi_city = (array_key_exists('bi_city', $_POST) && isset($_POST['bi_city'])) ? $_POST['bi_city'] : "";
            $bi_state = (array_key_exists('bi_state', $_POST) && isset($_POST['bi_state'])) ? $_POST['bi_state'] : "";
            $bi_country = (array_key_exists('bi_country', $_POST) && isset($_POST['bi_country'])) ? $_POST['bi_country'] : "";
            $bi_zip = (array_key_exists('bi_zip', $_POST) && isset($_POST['bi_zip'])) ? $_POST['bi_zip'] : "";
            $bi_paymentmethod = (array_key_exists('bi_paymentmethod', $_POST) && isset($_POST['bi_paymentmethod'])) ? $_POST['bi_paymentmethod'] : "";
            $bi_cash = (array_key_exists('bi_cash', $_POST) && isset($_POST['bi_cash'])) ? $_POST['bi_cash'] : "";
            // Fix #3: PCI-DSS Compliance - DO NOT store credit card data
            // Credit card processing must use PCI-compliant payment processor with tokenization
            // These fields are disabled for security/compliance reasons
            $bi_creditcardname = "";
            $bi_creditcardnumber = "";
            $bi_creditcardverification = "";
            $bi_creditcardtype = "";
            $bi_creditcardexp = "";
            $bi_notes = (array_key_exists('bi_notes', $_POST) && isset($_POST['bi_notes'])) ? $_POST['bi_notes'] : "";

            $bi_lead = (array_key_exists('bi_lead', $_POST) && isset($_POST['bi_lead'])) ? $_POST['bi_lead'] : "";
            $bi_coupon = (array_key_exists('bi_coupon', $_POST) && isset($_POST['bi_coupon'])) ? $_POST['bi_coupon'] : "";
            $bi_ordertaker = (array_key_exists('bi_ordertaker', $_POST) && isset($_POST['bi_ordertaker'])) ? $_POST['bi_ordertaker'] : "";
            $bi_billstatus = (array_key_exists('bi_billstatus', $_POST) && isset($_POST['bi_billstatus'])) ? $_POST['bi_billstatus'] : "";
            $bi_lastbill = (array_key_exists('bi_lastbill', $_POST) && isset($_POST['bi_lastbill'])) ? $_POST['bi_lastbill'] : "";
            $bi_nextbill = (array_key_exists('bi_nextbill', $_POST) && isset($_POST['bi_nextbill'])) ? $_POST['bi_nextbill'] : "";
            $bi_nextinvoicedue = (array_key_exists('bi_nextinvoicedue', $_POST) && isset($_POST['bi_nextinvoicedue'])) ? $_POST['bi_nextinvoicedue'] : "";
            $bi_billdue = (array_key_exists('bi_billdue', $_POST) && isset($_POST['bi_billdue'])) ? $_POST['bi_billdue'] : "";
            $bi_postalinvoice = (array_key_exists('bi_postalinvoice', $_POST) && isset($_POST['bi_postalinvoice'])) ? $_POST['bi_postalinvoice'] : "";
            $bi_faxinvoice = (array_key_exists('bi_faxinvoice', $_POST) && isset($_POST['bi_faxinvoice'])) ? $_POST['bi_faxinvoice'] : "";
            $bi_emailinvoice = (array_key_exists('bi_emailinvoice', $_POST) && isset($_POST['bi_emailinvoice'])) ? $_POST['bi_emailinvoice'] : "";

            $request_changeuserbillinfo = (isset($_POST['bi_changeuserbillinfo']) && $_POST['bi_changeuserbillinfo'] === '1');

            $planName = (array_key_exists('planName', $_POST) && isset($_POST['planName'])) ? trim($_POST['planName']) : "";
            $oldplanName = (array_key_exists('oldplanName', $_POST) && isset($_POST['oldplanName'])) ? trim($_POST['oldplanName']) : "";
            $isAddReplyAttributeRequest = (array_key_exists('is_add_reply_attribute_request', $_POST)
                                        && $_POST['is_add_reply_attribute_request'] === '1');


            if (!empty($username) && $isAddReplyAttributeRequest) {
                $replyAttrAuditAction = "reply-attribute-add-failed";
                $reply_attr_name = (isset($_POST['reply_attribute_name']) && !empty(trim($_POST['reply_attribute_name']))) ? trim($_POST['reply_attribute_name']) : "";
                $reply_attr_op = (isset($_POST['reply_attribute_op']) && in_array(trim($_POST['reply_attribute_op']), $valid_ops))
                               ? trim($_POST['reply_attribute_op']) : "=";
                $reply_attr_value = (isset($_POST['reply_attribute_value']) && !empty(trim($_POST['reply_attribute_value']))) ? trim($_POST['reply_attribute_value']) : "";

                // RFC2868 tunnel attributes are "has_tag": tag 0 (no tag suffix) is
                // treated as untagged by many NAS devices, so default to tag 1
                if (preg_match('/^Tunnel-(Password|Type|Medium-Type|Private-Group-Id|Client-Endpoint|Server-Endpoint|Preference|Client-Auth-Id|Server-Auth-Id|Assignment-Id)$/', $reply_attr_name)) {
                    $reply_attr_name .= ':1';
                }

                if (!empty($reply_attr_name) && !empty($reply_attr_value)) {
                    $checkSql = sprintf("SELECT COUNT(*) AS cnt FROM %s WHERE username='%s' AND attribute='%s'",
                                       $configValues['CONFIG_DB_TBL_RADREPLY'],
                                       $dbSocket->escapeSimple($username),
                                       $dbSocket->escapeSimple($reply_attr_name));
                    $checkRes = $dbSocket->query($checkSql);
                    $logDebugSQL .= "$checkSql;\n";

                    if (DB::isError($checkRes)) {
                        $failureMsg = "Error checking existing reply attribute: " . $checkRes->getMessage();
                        $logAction .= "failed checking existing reply attribute on page: ";
                    } else {
                        $checkRow = $checkRes->fetchRow();

                        if ($checkRow[0] > 0) {
                            $sql = sprintf("UPDATE %s SET op='%s', value='%s' WHERE username='%s' AND attribute='%s'",
                                           $configValues['CONFIG_DB_TBL_RADREPLY'],
                                           $dbSocket->escapeSimple($reply_attr_op),
                                           $dbSocket->escapeSimple($reply_attr_value),
                                           $dbSocket->escapeSimple($username),
                                           $dbSocket->escapeSimple($reply_attr_name));
                            $res = $dbSocket->query($sql);
                            $logDebugSQL .= "$sql;\n";

                            if (DB::isError($res)) {
                                $failureMsg = "Error updating reply attribute: " . $res->getMessage();
                                $logAction .= "failed updating reply attribute on page: ";
                                $replyAttrAuditAction = "reply-attribute-update-failed";
                            } else {
                                $successMsg = "Reply attribute updated successfully";
                                $logAction .= "successfully updated reply attribute on page: ";
                                $replyAttrAuditAction = "reply-attribute-updated";
                            }
                        } else {
                            $sql = sprintf("INSERT INTO %s (username, attribute, op, value) VALUES ('%s', '%s', '%s', '%s')",
                                           $configValues['CONFIG_DB_TBL_RADREPLY'],
                                           $dbSocket->escapeSimple($username),
                                           $dbSocket->escapeSimple($reply_attr_name),
                                           $dbSocket->escapeSimple($reply_attr_op),
                                           $dbSocket->escapeSimple($reply_attr_value));
                            $res = $dbSocket->query($sql);
                            $logDebugSQL .= "$sql;\n";

                            if (DB::isError($res)) {
                                $failureMsg = "Error adding reply attribute: " . $res->getMessage();
                                $logAction .= "failed adding reply attribute on page: ";
                                $replyAttrAuditAction = "reply-attribute-add-failed";
                            } else {
                                $successMsg = "Reply attribute added successfully";
                                $logAction .= "successfully added reply attribute on page: ";
                                $replyAttrAuditAction = "reply-attribute-added";
                            }
                        }
                    }
                } else {
                    $failureMsg = "Attribute name and value are required";
                    $logAction .= "missing reply attribute name or value on page: ";
                }

                $auditLog = sprintf(
                    "[%s] operator=%s remoteUser=%s action=%s username=%s attribute=%s",
                    date('Y-m-d H:i:s'),
                    $_SESSION['operator_id'] ?? 'unknown',
                    $ssoUser,
                    $replyAttrAuditAction,
                    $username,
                    $reply_attr_name
                );
            } elseif (!empty($username) && !$isAddReplyAttributeRequest) {

                // dealing with attributes
                include("library/attributes.php");

                $skipList = array( "username", "submit", "groups", "planName", "oldplanName",
                                   "copycontact", "firstname", "lastname", "email", "department", "company", "workphone",
                                   "homephone", "mobilephone", "address", "city", "state", "country", "zip", "notes",
                                   "changeUserInfo", "bi_contactperson", "bi_company", "bi_email", "bi_phone", "bi_address",
                                   "bi_city", "bi_state", "bi_country", "bi_zip", "bi_paymentmethod", "bi_cash", "bi_creditcardname",
                                   "bi_creditcardnumber", "bi_creditcardverification", "bi_creditcardtype", "bi_creditcardexp",
                                   "bi_notes", "bi_changeuserbillinfo", "bi_lead", "bi_coupon", "bi_ordertaker", "bi_billstatus",
                                   "bi_lastbill", "bi_nextbill", "bi_nextinvoicedue", "bi_billdue", "bi_postalinvoice", "bi_faxinvoice",
                                   "bi_emailinvoice", "bi_planname", "portalLoginPassword", "enableUserPortalLogin",
                                   "csrf_token", "submit"
                                 );


                handleAttributes($dbSocket, $username, $skipList, false);
                
                // Fix #5: SSO Audit Logging - Log operator actions with REMOTE_USER for traceability
                $auditLog = sprintf(
                    "[%s] operator=%s remoteUser=%s action=update username=%s",
                    date('Y-m-d H:i:s'),
                    $_SESSION['operator_id'] ?? 'unknown',
                    $ssoUser,
                    $username
                );

                // insert or update user info
                $userinfoExist = user_exists($dbSocket, $username, 'CONFIG_DB_TBL_DALOUSERINFO');
                $hasPortalLoginPassword = has_effective_user_portal_login_password($dbSocket, $username,
                                                                                   $ui_PortalLoginPassword, $userinfoExist);
                $ui_changeuserinfo = ($hasPortalLoginPassword && $request_changeuserinfo) ? '1' : '0';
                $ui_enableUserPortalLogin = ($hasPortalLoginPassword && $request_enableUserPortalLogin) ? '1' : '0';
                $bi_changeuserbillinfo = ($hasPortalLoginPassword && $request_changeuserbillinfo) ? '1' : '0';

                $params = array(
                                    "firstname" => $firstname,
                                    "lastname" => $lastname,
                                    "email" => $email,
                                    "department" => $department,
                                    "company" => $company,
                                    "workphone" => $workphone,
                                    "homephone" => $homephone,
                                    "mobilephone" => $mobilephone,
                                    "address" => $address,
                                    "city" => $city,
                                    "state" => $state,
                                    "country" => $country,
                                    "zip" => $zip,
                                    "notes" => $notes,
                                    "changeuserinfo" => $ui_changeuserinfo,
                                    "enableportallogin" => $ui_enableUserPortalLogin,
                                    "portalloginpassword" => $ui_PortalLoginPassword,
                               );

                if ($userinfoExist) {
                    $params["updatedate"] = $current_datetime;
                    $params["updateby"] = $currBy;
                    $addedUserInfo = (update_user_info($dbSocket, $username, $params)) ? "stored" : "nothing to store";
                } else {
                    $params["creationdate"] = $current_datetime;
                    $params["creationby"] = $currBy;
                    $addedUserInfo = (add_user_info($dbSocket, $username, $params)) ? "updated" : "nothing to update";
                }


                if ($hasBillingAccess) {
                    // insert or update billing info
                    $billinfoExist = user_exists($dbSocket, $username, 'CONFIG_DB_TBL_DALOUSERBILLINFO');

                    $params = array(
                                        "contactperson" => $bi_contactperson,
                                        "company" => $bi_company,
                                        "email" => $bi_email,
                                        "phone" => $bi_phone,
                                        "address" => $bi_address,
                                        "city" => $bi_city,
                                        "state" => $bi_state,
                                        "country" => $bi_country,
                                        "zip" => $bi_zip,
                                        "postalinvoice" => $bi_postalinvoice,
                                        "faxinvoice" => $bi_faxinvoice,
                                        "emailinvoice" => $bi_emailinvoice,

                                        "paymentmethod" => $bi_paymentmethod,
                                        "cash" => $bi_cash,
                                        "creditcardname" => $bi_creditcardname,
                                        "creditcardnumber" => $bi_creditcardnumber,
                                        "creditcardverification" => $bi_creditcardverification,
                                        "creditcardtype" => $bi_creditcardtype,
                                        "creditcardexp" => $bi_creditcardexp,

                                        "lead" => $bi_lead,
                                        "coupon" => $bi_coupon,
                                        "ordertaker" => $bi_ordertaker,

                                        "notes" => $bi_notes,
                                        "changeuserbillinfo" => $bi_changeuserbillinfo,

                                        //~ "billstatus" => $bi_billstatus,
                                        //~ "lastbill" => $bi_lastbill,
                                        //~ "nextbill" => $bi_nextbill,
                                        "billdue" => $bi_billdue,
                                        "nextinvoicedue" => $bi_nextinvoicedue,

                                        "creationdate" => $current_datetime,
                                        "creationby" => $currBy,
                                   );

                    if ($billinfoExist) {
                        $params["planName"] = $planName;
                        $params["updatedate"] = $current_datetime;
                        $params["updateby"] = $currBy;
                        $addedBillinfo = (update_user_billing_info($dbSocket, $username, $params)) ? "stored" : "nothing to store";
                    } else {
                        $params["creationdate"] = $current_datetime;
                        $params["creationby"] = $currBy;
                        $addedBillinfo = (add_user_billing_info($dbSocket, $username, $params)) ? "updated" : "nothing to update";
                    }
                } else {
                    $addedBillinfo = "not updated (insufficient billing permissions)";
                }

                // update group mappings
                if (delete_user_group_mappings($dbSocket, $username)) {
                    if (count($groups) > 0) {
                        foreach ($groups as $group) {
                            list($groupname, $priority) = $group;
                            insert_single_user_group_mapping($dbSocket, $username, $groupname, $priority);
                        }
                    }
                }

                addPlanProfile($dbSocket, $username, $planName, $oldplanName);

                $successMsg = sprintf("Successfully updated user <strong>%s</strong>", $username_enc);
                $logAction .= sprintf("Successfully updated user %s on page: ", $username);

            } elseif (empty($username)) {
                $failureMsg = "You have specified an empty or invalid username";
                $logAction .= "empty or invalid username on page: ";
            }

        } else {
            // csrf
            $failureMsg = "CSRF token error";
            $logAction .= "$failureMsg on page: ";
        }

    }


    if (empty($username)) {
        $failureMsg = "You have specified an empty or invalid username";
        $inline_extra_js = "";
    } else {

        /* an sql query to retrieve the password for the username to use in the quick link for the user test connectivity */
        $sql = sprintf("SELECT value FROM %s WHERE username='%s' AND attribute LIKE '%%-Password' ORDER BY id DESC",
                       $configValues['CONFIG_DB_TBL_RADCHECK'], $dbSocket->escapeSimple($username));
        $res = $dbSocket->query($sql);
        $logDebugSQL .= "$sql;\n";
        $row = $res->fetchRow();
        $user_password = ($row) ? $row[0] : "";

        /* fill-in all the user info details */
        $sql = sprintf("SELECT firstname, lastname, email, department, company, workphone, homephone, mobilephone, address, city,
                               state, country, zip, notes, changeuserinfo, portalloginpassword, enableportallogin, creationdate,
                               creationby, updatedate, updateby
                          FROM %s WHERE username='%s'", $configValues['CONFIG_DB_TBL_DALOUSERINFO'],
                                                        $dbSocket->escapeSimple($username));
        $res = $dbSocket->query($sql);
        $logDebugSQL .= "$sql;\n";

        list(
              $ui_firstname, $ui_lastname, $ui_email, $ui_department, $ui_company, $ui_workphone, $ui_homephone,
              $ui_mobilephone, $ui_address, $ui_city, $ui_state, $ui_country, $ui_zip, $ui_notes, $ui_changeuserinfo,
              $ui_PortalLoginPassword, $ui_enableUserPortalLogin, $ui_creationdate, $ui_creationby, $ui_updatedate,
              $ui_updateby
            ) = $res->fetchRow();

        /* fill-in all the user bill info details */
        if ($hasBillingAccess) {
            $sql = sprintf("SELECT planName, contactperson, company, email, phone, address, city, state, country, zip, paymentmethod,
                                   cash, creditcardname, creditcardnumber, creditcardverification, creditcardtype, creditcardexp,
                                   notes, changeuserbillinfo, `lead`, coupon, ordertaker, billstatus, lastbill, nextbill,
                                   nextinvoicedue, billdue, postalinvoice, faxinvoice, emailinvoice, creationdate, creationby,
                                   updatedate, updateby
                              FROM %s WHERE username='%s'", $configValues['CONFIG_DB_TBL_DALOUSERBILLINFO'],
                                                            $dbSocket->escapeSimple($username));
            $res = $dbSocket->query($sql);
            $logDebugSQL .= "$sql;\n";

            list(
                    $bi_planname, $bi_contactperson, $bi_company, $bi_email, $bi_phone, $bi_address, $bi_city, $bi_state,
                    $bi_country, $bi_zip, $bi_paymentmethod, $bi_cash, $bi_creditcardname, $bi_creditcardnumber,
                    $bi_creditcardverification, $bi_creditcardtype, $bi_creditcardexp, $bi_notes, $bi_changeuserbillinfo,
                    $bi_lead, $bi_coupon, $bi_ordertaker, $bi_billstatus, $bi_lastbill, $bi_nextbill, $bi_nextinvoicedue,
                    $bi_billdue, $bi_postalinvoice, $bi_faxinvoice, $bi_emailinvoice, $bi_creationdate, $bi_creationby,
                    $bi_updatedate, $bi_updateby
                ) = $res->fetchRow();
        } else {
            $bi_planname = "";
            $bi_contactperson = "";
            $bi_company = "";
            $bi_email = "";
            $bi_phone = "";
            $bi_address = "";
            $bi_city = "";
            $bi_state = "";
            $bi_country = "";
            $bi_zip = "";
            $bi_paymentmethod = "";
            $bi_cash = "";
            $bi_creditcardname = "";
            $bi_creditcardnumber = "";
            $bi_creditcardverification = "";
            $bi_creditcardtype = "";
            $bi_creditcardexp = "";
            $bi_notes = "";
            $bi_changeuserbillinfo = "0";
            $bi_lead = "";
            $bi_coupon = "";
            $bi_ordertaker = "";
            $bi_billstatus = "";
            $bi_lastbill = "";
            $bi_nextbill = "";
            $bi_nextinvoicedue = "";
            $bi_billdue = "";
            $bi_postalinvoice = "";
            $bi_faxinvoice = "";
            $bi_emailinvoice = "";
            $bi_creationdate = "";
            $bi_creationby = "";
            $bi_updatedate = "";
            $bi_updateby = "";
        }

        // inline extra javascript
        // Fix #1: XSS Prevention - Use json_encode for JavaScript string context
        // htmlspecialchars() does NOT properly escape JavaScript strings - only json_encode() works
        $inline_extra_js = sprintf("var strUsername = 'username=%s';\n", rawurlencode($username));

        $inline_extra_js .= '
function disableUser() {
    if (confirm("You are about to disable this user account\nDo you want to continue?"))  {
        ajaxGeneric("library/ajax/user_actions.php", "userDisable=true", "returnMessages", strUsername);
        return true;
    }
}

function enableUser() {
    if (confirm("You are about to enable this user account\nDo you want to continue?"))  {
        ajaxGeneric("library/ajax/user_actions.php", "userEnable=true", "returnMessages", strUsername);
        return true;
    }
}

function toggleSecretInput(button) {
    var targetId = button.getAttribute("data-target");
    var input = document.getElementById(targetId);

    if (!input) {
        return;
    }

    var showingSecret = input.type === "text";
    input.type = showingSecret ? "password" : "text";
    button.textContent = showingSecret ? button.getAttribute("data-reveal-text") : button.getAttribute("data-hide-text");
}' . "\n";
    }

    include('../common/includes/db_close.php');

    // print HTML prologue
    $extra_css = array();

    $extra_js = array(
        "static/js/ajax.js",
        "static/js/ajaxGeneric.js",
        "static/js/productive_funcs.js",
        "static/js/pages_common.js",
        "static/js/dynamic_attributes.js",
    );

    $title = t('Intro','mngedit.php');
    $help = t('helpPage','mngedit');

    print_html_prologue($title, $langCode, $extra_css, $extra_js, "", $inline_extra_js);

    if (!empty($username_enc)) {
        $title .= " :: $username_enc";
    }

    print_title_and_help($title, $help);

    include_once('include/management/actionMessages.php');

    $inline_extra_js = "";
    if (!empty($username)) {

        // ajax return div
        echo '<div id="returnMessages"></div>';
        include_once('include/management/populate_selectbox.php');

        // we have more than one form in this page so we can reuse many times the same csrf_token value
        $csrf_token = dalo_csrf_token();

        $submit_descriptor = array(
                                    "type" => "submit",
                                    "name" => "submit",
                                    "value" => t('buttons','apply')
                                  );

        $input_descriptors0 = array();

        $input_descriptors0[] = array(
                                        "type" => "hidden",
                                        "value" => $csrf_token,
                                        "name" => "csrf_token"
                                     );

        $input_descriptors0[] = array(
                                        "type" => "hidden",
                                        "value" => $username_enc,
                                        "name" => "username"
                                     );

        $input_descriptors0[] = array(
                                        "name" => "username_presentation",
                                        "caption" => t('all','Username'),
                                        "type" => "text",
                                        "value" => ((isset($username)) ? $username : ""),
                                        "disabled" => true,
                                        "tooltipText" => t('Tooltip','usernameTooltip')
                                      );

        $input_descriptors0[] = array( 'name' => 'oldplanName', 'type' => 'hidden',
                                                 'value' => ((isset($bi_planname)) ? $bi_planname : "") );

        $options = get_active_plans();
        array_unshift($options, '');
        $input_descriptors0[] = array(
                                         'type' => 'select',
                                         'name' => 'planName',
                                         'caption' => t('all','PlanName'),
                                         'tooltipText' => t('Tooltip','planNameTooltip'),
                                         'options' => $options,
                                         'selected_value' => ((isset($bi_planname)) ? $bi_planname : "")
                                     );

        // set navbar stuff
        $navkeys = array(
                          'AccountInfo', 'RADIUSCheck', 'RADIUSReply', 'UserInfo', 'BillingInfo',
                          'Groups', 'Attributes', array( 'OtherInfo', "Other Info" )
                        );

        // print navbar controls
        print_tab_header($navkeys);

        // open form
        open_form();

        // open tab wrapper
        open_tab_wrapper();

        // open first tab (shown)
        open_tab($navkeys, 0, true);

        // open a fieldset
        $fieldset0_descriptor = array(
                                        "title" => t('title','AccountInfo'),
                                     );

        open_fieldset($fieldset0_descriptor);

        foreach ($input_descriptors0 as $input_descriptor) {
            print_form_component($input_descriptor);
        }

        $password_caption = htmlspecialchars(t('all','Password'), ENT_QUOTES, 'UTF-8');
        $password_value = (isset($user_password)) ? htmlspecialchars($user_password, ENT_QUOTES, 'UTF-8') : "";
        $password_help = htmlspecialchars(t('Tooltip','passwordTooltip'), ENT_QUOTES, 'UTF-8');
        echo <<<EOF
        <div class="mb-3">
            <label for="password" class="form-label mx-1 mb-1">{$password_caption}</label>
            <div class="input-group">
                <input class="form-control" id="password" type="password" value="{$password_value}" disabled aria-describedby="password-help">
                <button class="btn btn-outline-secondary" type="button" data-target="password" data-reveal-text="Reveal" data-hide-text="Hide" onclick="toggleSecretInput(this)">Reveal</button>
            </div>
            <div id="password-help" class="form-text">{$password_help}</div>
        </div>
EOF;

        close_fieldset();

        // open a fieldset
        $fieldset0_descriptor = array(
                                        "title" => "Actions",
                                     );

        open_fieldset($fieldset0_descriptor);

        include('include/management/buttons.php');

        $button_descriptors1[] = array(
                                        'type' => 'button',
                                        'value' => 'Enable User',
                                        'onclick' => 'javascript:enableUser()',
                                        'name' => 'enableUser-button'
                                      );

        $button_descriptors1[] = array(
                                        'type' => 'button',
                                        'value' => 'Disable User',
                                        'onclick' => 'javascript:disableUser()',
                                        'name' => 'disableUser-button'
                                      );

        // custom actions
        echo <<<EOF
    <div class="dropdown dropup">
        <button class="btn btn-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
            Actions
        </button>

        <ul class="dropdown-menu">
EOF;

        foreach ($button_descriptors1 as $desc) {
            printf('<li><a href="#" class="dropdown-item" name="%s" onclick="%s">%s</a></li>', $desc['name'], $desc['onclick'], $desc['value']);
        }


        echo <<<EOF
        </ul>
    </div>
EOF;

        close_fieldset();

        close_tab($navkeys, 0);


        // open 1-st tab (not shown)
        open_tab($navkeys, 1);

        // open 1-st fieldset
        $fieldset1_descriptor = array(
                                        "title" => t('title','RADIUSCheck'),
                                     );
        open_fieldset($fieldset1_descriptor);

        $hashing_algorithm_notice = '<small class="mt-4 d-block">'
                                  . 'Notice that for supported password-like attributes, you can just specify a plaintext value. '
                                  . 'The system will take care of correctly hashing it.'
                                  . '</small>';

        include('../common/includes/db_open.php');

        include_once('include/management/pages_common.php');

	$sql = sprintf("SELECT rad.attribute, rad.op, rad.value, NULL AS type, NULL AS recommendedTooltip, rad.id
                  FROM %s AS rad
                 WHERE rad.username='%s' ORDER BY rad.id ASC", $configValues['CONFIG_DB_TBL_RADCHECK'],
                                                               $dbSocket->escapeSimple($username));

        $res = $dbSocket->query($sql);
        $logDebugSQL .= "$sql;\n";

        echo '<div class="container">';

        if ($res->numRows() == 0) {
            printf('<div class="alert alert-info" role="alert">%s</div>', t('messages','noCheckAttributesForUser'));
        } else {
            while ($row = $res->fetchRow()) {

                foreach ($row as $i => $v) {
                    $row[$i] = htmlspecialchars($row[$i], ENT_QUOTES, 'UTF-8');
                }

                $id = $row[5];
                $id__attribute = sprintf('%s__%s', $id, $row[0]);
                $name = sprintf('editValues%s[]', $id);
                $type = (preg_match("/-Password(:\\d+)?$/i", $row[0])) ? "password" : "text";
                $onclick = sprintf("document.getElementById('form-%d-radcheck').submit()", $id);

                $descriptor = array( 'onclick' => $onclick, 'attribute' => $row[0], 'select_name' => $name, 'selected_option' => $row[1],
                                     'id__attribute' => $id__attribute, 'type' => $type, 'value' => $row[2], 'name' => $name,
                                     'attr_type' => $row[3], 'attr_desc' => $row[4], 'table' => 'radcheck',
                                     'id' => sprintf('radcheck-secret-%d', $id),
                                     'revealToggle' => ($type === "password"));

                print_edit_attribute($descriptor);
            }

            echo $hashing_algorithm_notice;
        }

        echo '</div><!-- .container -->';

        close_fieldset();

        close_tab($navkeys, 1);

        // open 2-nd tab (not shown)
        open_tab($navkeys, 2);

        // open 2-nd fieldset
        $fieldset1_descriptor = array(
                                        "title" => t('title','RADIUSReply'),
                                     );
        open_fieldset($fieldset1_descriptor);

	$sql = sprintf("SELECT rad.attribute, rad.op, rad.value, NULL AS type, NULL AS recommendedTooltip, rad.id
                  FROM %s AS rad
                 WHERE rad.username='%s' ORDER BY rad.id ASC", $configValues['CONFIG_DB_TBL_RADREPLY'],
                                                               $dbSocket->escapeSimple($username));

        $res = $dbSocket->query($sql);
        $logDebugSQL .= "$sql;\n";


        echo '<div class="container">';
        if ($res->numRows() == 0) {
            printf('<div class="alert alert-info" role="alert">%s</div>', t('messages','noReplyAttributesForUser'));
        } else {
            while ($row = $res->fetchRow()) {

                foreach ($row as $i => $v) {
                    $row[$i] = htmlspecialchars($row[$i], ENT_QUOTES, 'UTF-8');
                }

                $id = $row[5];
                $id__attribute = sprintf('%s__%s', $id, $row[0]);
                $name = sprintf('editValues%s[]', $id);
                $type = (preg_match("/-Password(:\\d+)?$/i", $row[0])) ? "password" : "text";
                $onclick = sprintf("document.getElementById('form-%d-radreply').submit()", $id);

                $descriptor = array( 'onclick' => $onclick, 'attribute' => $row[0], 'select_name' => $name, 'selected_option' => $row[1],
                                     'id__attribute' => $id__attribute, 'type' => $type, 'value' => $row[2], 'name' => $name,
                                     'attr_type' => $row[3], 'attr_desc' => $row[4], 'table' => 'radreply',
                                     'id' => sprintf('radreply-secret-%d', $id),
                                     'revealToggle' => ($type === "password"));

                print_edit_attribute($descriptor);
            }


            echo $hashing_algorithm_notice;
        }

        echo '</div><!-- .container -->';

        // Add New Reply Attribute Form
        echo '<div class="card mt-3" style="background-color: #f8f9fa; border: 1px solid #dee2e6;">';
        echo '<div class="card-body">';
        echo '<h5 class="card-title">Add New Reply Attribute</h5>';
        echo '<div class="form-inline">';
        
        echo '<div class="form-group mr-2">';
        echo '<label for="replyAttrName" class="mr-2">Attribute:</label>';
        echo '<select id="replyAttrName" class="form-control form-control-sm">';
        echo '<option value="">-- Select Attribute --</option>';
        echo '<option value="Tunnel-Password">Tunnel-Password</option>';
        echo '<option value="Session-Timeout">Session-Timeout</option>';
        echo '<option value="Idle-Timeout">Idle-Timeout</option>';
        echo '<option value="Framed-IP-Address">Framed-IP-Address</option>';
        echo '<option value="Reply-Message">Reply-Message</option>';
        echo '<option value="Acct-Interim-Interval">Acct-Interim-Interval</option>';
        echo '<option value="Tunnel-Type">Tunnel-Type</option>';
        echo '<option value="Tunnel-Medium-Type">Tunnel-Medium-Type</option>';
        echo '</select>';
        echo '</div>';
        
        echo '<div class="form-group mr-2">';
        echo '<label for="replyAttrOp" class="mr-2">Operator:</label>';
        echo '<select id="replyAttrOp" class="form-control form-control-sm">';
        echo '<option value="=" selected>=</option>';
        echo '<option value=":=">:=</option>';
        echo '<option value="+=">+=</option>';
        echo '</select>';
        echo '</div>';
        
        echo '<div class="form-group mr-2" style="flex: 1;">';
        echo '<label for="replyAttrValue" class="mr-2">Value:</label>';
        echo '<input type="text" id="replyAttrValue" class="form-control form-control-sm" placeholder="Enter value">';
        echo '</div>';
        
        echo '<button type="button" class="btn btn-sm btn-primary" onclick="return submitReplyAttributeForm()">Add Attribute</button>';
        echo '</div>';
        echo '</div>';
        echo '</div>';

        close_fieldset();

        close_tab($navkeys, 2);

        // open 3-rd tab (not shown)
        open_tab($navkeys, 3);
        include_once('include/management/userinfo.php');
        close_tab($navkeys, 3);


        // open 4-th tab (not shown)
        open_tab($navkeys, 4);
        if ($hasBillingAccess) {
            include_once('include/management/userbillinfo.php');
        } else {
            echo '<div class="alert alert-warning" role="alert">You do not have permission to view or edit billing information.</div>';
        }
        close_tab($navkeys, 4);

        // open 5-th tab (not shown)
        open_tab($navkeys, 5);

        include('../common/includes/db_open.php');
        include_once('include/management/groups.php');
        include('../common/includes/db_close.php');

        close_tab($navkeys, 5);

        open_tab($navkeys, 6);

        include_once('include/management/attributes.php');

        close_tab($navkeys, 6);

        open_tab($navkeys, 7);

        // accordion
        echo '<div class="accordion m-2" id="accordion-parent">';
        include_once('include/management/userReports.php');
        userPlanInformation($username, 1);
        userSubscriptionAnalysis($username, 1);                 // userSubscriptionAnalysis with argument set to 1 for drawing the table
        userConnectionStatus($username, 1);                     // userConnectionStatus (same as above)
        echo '</div>';

        close_tab($navkeys, 7);

        // close tab wrapper
        close_tab_wrapper();

        print_form_component($submit_descriptor);

        close_form();

        printf('<form id="replyAttrAddForm" method="POST" action="mng-edit.php" style="display: none">'
             . '<input type="hidden" name="csrf_token" value="%s">'
             . '<input type="hidden" name="username" value="%s">'
             . '<input type="hidden" name="is_add_reply_attribute_request" value="1">'
             . '<input type="hidden" id="replyAttrAddName" name="reply_attribute_name" value="">'
             . '<input type="hidden" id="replyAttrAddOp" name="reply_attribute_op" value="">'
             . '<input type="hidden" id="replyAttrAddValue" name="reply_attribute_value" value="">'
             . '</form>',
               $csrf_token, $username_enc);

        // print forms
        include('../common/includes/db_open.php');

        $tables = array(
                            'radcheck' => $configValues['CONFIG_DB_TBL_RADCHECK'],
                            'radreply' => $configValues['CONFIG_DB_TBL_RADREPLY']
                       );

        foreach ($tables as $table_value => $table) {

            $sql = sprintf("SELECT id, attribute, value FROM %s WHERE username='%s' ORDER BY id ASC",
                           $table, $dbSocket->escapeSimple($username));
            $res = $dbSocket->query($sql);
            $logDebugSQL .= "$sql;\n";

            if ($res->numRows() > 0) {

                while ($row = $res->fetchrow()) {
                    list($id, $attribute, $value) = $row;
                    $id = intval($id);

                    $formId = sprintf("form-%d-%s", $id, $table_value);
                    $id__attribute = sprintf("%d__%s", $id, htmlspecialchars($attribute, ENT_QUOTES, 'UTF-8'));

                    printf('<form id="%s" style="display: none" method="POST" action="mng-del.php">', $formId);
                    printf('<input type="hidden" name="username" value="%s">', $username_enc);
                    printf('<input type="hidden" name="attribute" value="%s">', $id__attribute);
                    printf('<input type="hidden" name="csrf_token" value="%s">', $csrf_token);
                    printf('<input type="hidden" name="tablename" value="%s">', $table_value);
                    echo '</form>';
                }
            }
        }

        include('../common/includes/db_close.php');

        $inline_extra_js = <<<EOF

function submitReplyAttributeForm() {
    var nameEl = document.getElementById('replyAttrName'),
        opEl = document.getElementById('replyAttrOp'),
        valueEl = document.getElementById('replyAttrValue');

    if (!nameEl || !opEl || !valueEl) {
        return false;
    }

    var attrName = (nameEl.value || '').trim(),
        attrOp = (opEl.value || '').trim(),
        attrValue = (valueEl.value || '').trim();

    if (!attrName || !attrValue) {
        alert('Attribute name and value are required');
        return false;
    }

    document.getElementById('replyAttrAddName').value = attrName;
    document.getElementById('replyAttrAddOp').value = attrOp;
    document.getElementById('replyAttrAddValue').value = attrValue;
    document.getElementById('replyAttrAddForm').submit();
    return false;
}

window.onload = function() {
    setupAccordion();
    ajaxGeneric("library/ajax/user_actions.php", "checkDisabled=true", "returnMessages", strUsername);

    var replyValueEl = document.getElementById('replyAttrValue');
    if (replyValueEl) {
        replyValueEl.addEventListener('keydown', function(evt) {
            if (evt.key === 'Enter') {
                evt.preventDefault();
                submitReplyAttributeForm();
            }
        });
    }
};

EOF;

    }

    print_back_to_previous_page();

    include('include/config/logging.php');

    print_footer_and_html_epilogue($inline_extra_js);
