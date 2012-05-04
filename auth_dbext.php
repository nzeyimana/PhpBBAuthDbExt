<?php
/**
* External MySQL auth plug-in for phpBB3
*
* Authentication plug-ins is largely down to Sergey Kanareykin, our thanks to him.
*
* @package login
* @version $Id: auth_dbext.php 8602 2009-04-09 16:38:27Z nzeyimana $
* @copyright NONE: use as you see fit but no guarantees
* @license NONE: use as you see fit but no guarantees
*
*/

/**
* @ignore
*/
if (!defined('IN_PHPBB'))
{
    exit;
}

/**
*
* @return boolean|string false if the user is identified and else an error message
*/

function init_dbext()
{
    // TODO: do any needed initialization
}

/**
* Login function
*/
function login_dbext(&$username, &$password)
{
    global $db;
    
    // do not allow empty password
    if (!$password)
    {
        return array(
            'status'    => LOGIN_ERROR_PASSWORD,
            'error_msg' => 'NO_PASSWORD_SUPPLIED',
            'user_row'  => array('user_id' => ANONYMOUS),
        );
    }

    if (!$username)
    {
        return array(
            'status'    => LOGIN_ERROR_USERNAME,
            'error_msg' => 'LOGIN_ERROR_USERNAME',
            'user_row'  => array('user_id' => ANONYMOUS),
        );
    }
    
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Note: on my systems, I include these following lines from an external file that is not web-accessible 
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $db_host      = "localhost"; // Here goes the MySQL server address, hostname or IP
    $db_user      = "username";  // Here goes the MySQL user allowed to read the table below (GRANT SELECT ON ....)
    $db_password  = "passwd";    // Here should go the password associated with the above user
    $db_database  = "dbName";    // Here goes the Database containing the table below
    $db_table     = "tblUsers";  // Here will goes the table list users allowed to login into PHPBB   
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $col_username = "username";
    $col_password = "password";
    $hashMethod   = "sha1"; // Can be one of:  md5, sha1, plain
                            // In case you choose to use a non-standard hashing function, be 
                            // sure to change below where the $hashedPassword variable is created

    $objMySqli = new mysqli($db_host, $db_user, $db_password, $db_database);
    
    /* check connection */
    if (mysqli_connect_errno()) 
    {
        return array(
            'status'    => LOGIN_ERROR_EXTERNAL_AUTH,
            'error_msg' => 'LOGIN_ERROR_EXTERNAL_AUTH',
            'user_row'  => array('user_id' => ANONYMOUS),
        );
    }
    
    // Check the User/Password
    if($hashMethod == 'sha1')
    {
        $hashedPassword = sha1($password);
    } elseif($hashMethod == 'md5') {
        $hashedPassword = md5($password);
    } else {
        $hashedPassword = $password;
    }
    $sql = 
        "SELECT 11 as ID 
        FROM " . $db_table . " 
        WHERE 
            " . $col_username . " = '" . mysqli_real_escape_string($username)       . "' AND 
            " . $col_password . " = '" . mysqli_real_escape_string($hashedPassword) . "' 
            ";
    
    if ( $result = $objMySqli->query($sql) )
    {
        if ( $result->num_rows <= 0 )
        {
            return array(
                'status'    => LOGIN_ERROR_USERNAME,
                'error_msg' => 'LOGIN_ERROR_USERNAME',
                'user_row'  => array('user_id' => ANONYMOUS),
            );
        }

        $sql = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type
            FROM ' . USERS_TABLE . "
            WHERE username = '" . $db->sql_escape($username) . "'";
        $result = $db->sql_query($sql);
        $row = $db->sql_fetchrow($result);
        $db->sql_freeresult($result);

        if ($row)
        {
            // User inactive...
            if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
            {
                return array(
                    'status'    => LOGIN_ERROR_ACTIVE,
                    'error_msg' => 'ACTIVE_ERROR',
                    'user_row'  => $row,
                );
            }
    
            // Successful login...
            return array(
                'status'    => LOGIN_SUCCESS,
                'error_msg' => false,
                'user_row'  => $row,
            );
        }

        // this is the user's first login so create an empty profile
        return array(
            'status'    => LOGIN_SUCCESS_CREATE_PROFILE,
            'error_msg' => false,
            'user_row'  => user_row_dbext($username, sha1($password)),
        );
    } else {
        // TODO: Handle this situation
    }

    // Not logged in using the external DB
    return array(
        'status'    => LOGIN_ERROR_EXTERNAL_AUTH,
        'error_msg' => 'LOGIN_ERROR_EXTERNAL_AUTH',
        'user_row'  => array('user_id' => ANONYMOUS),
    );
}

/**
* This function generates an array which can be passed to the user_add function in order to create a user
*/
function user_row_dbext($username, $password)
{
    global $db, $config, $user;
    // first retrieve default group id
    $sql = 'SELECT group_id
        FROM ' . GROUPS_TABLE . "
        WHERE group_name = '" . $db->sql_escape('REGISTERED') . "'
            AND group_type = " . GROUP_SPECIAL;
    $result = $db->sql_query($sql);
    $row = $db->sql_fetchrow($result);
    $db->sql_freeresult($result);

    if (!$row)
    {
        trigger_error('NO_GROUP');
    }

    // generate user account data
    return array(
        'username'      => $username,
        'user_password' => phpbb_hash($password), // Note: on my side, I don't use this because I want all passwords to remain on the remote system
        'user_email'    => '', // You can retrieve this Email at the time the user is authenticated from the external table
        'group_id'      => (int) $row['group_id'],
        'user_type'     => USER_NORMAL,
        'user_ip'       => $user->ip,
    );
}

?>