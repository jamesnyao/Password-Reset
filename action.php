<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <title>LDAP Password Reset</title>
  <meta http-equiv="CACHE-CONTROL" content="NO-CACHE" />
  <meta http-equiv="PRAGMA" content="NO-CACHE" />
  <link rel="stylesheet" href='sysadmin.css' type='text/css' media="screen" />
</head>

<body>
  <div id='page-heading'>
	<h1 class='page-heading-title'>CS Department at Binghamton University<br />System Administration Support Interface</h1>
	<div class='page-heading-description'>
		<h2 class='page-heading-topic'>System Administration Support Page</h2>
		<p class='page-heading-description'>&nbsp;</p>
	</div>
	<hr />
  </div>

<?php

require "utils/request_utils.php";

$username = $_GET["username"];
$bnum = $_GET["bnum"];

// Lookup correct email address
$ldaphost = "ldaps://ldap.cs.binghamton.edu";
$ldapconn = ldap_connect($ldaphost)
        or die("Could not connect to ".$ldaphost); 
$dn = "ou=People,dc=cs,dc=binghamton,dc=edu";
$sr = ldap_search($ldapconn, $dn, "uid=".$username);
$ldapinfo = ldap_get_entries($ldapconn, $sr);
$emailaddr = ldap_get_bmail($ldapinfo);
$checkbnum = ldap_get_bnum($ldapinfo);

// Check if bnumber and username is correct.
if ($bnum == $checkbnum) {

    // Generate Token
    $token = generate_token($username);
    
    if ($token == "")
    {
        echo "<script type='text/javascript'>
                alert('Error');
                window.location.href='http://www2.cs.binghamton.edu/~jyao6/';
              </script>";
    }
    else
    {
        // Email    
        $msg = "You have requested to change your CS LDAP password.\n
                Click this link: www2.cs.binghamton.edu/~jyao6/return.php?token="
                .$token."\n";
        $header = "From: sysadmin@cs.binghamton.edu";
        mail($emailaddr, "CS LDAP password reset", $msg, $header);
        echo "<font size=\"4\">&emsp;Email with reset link sent to ".$emailaddr."</font>";
    }

// Bnumber not correct
}
else
{
    echo "<font size=\"4\">&emsp;Incorrect B-Number for this user</font>";
}

?>

</body>
</html>

