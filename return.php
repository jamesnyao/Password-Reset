<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">

<head>

<title>LDAP Password Reset</title>
<meta http-equiv="CACHE-CONTROL" content="NO-CACHE" />
<meta http-equiv="PRAGMA" content="NO-CACHE" />
<link rel="stylesheet" href='sysadmin.css' type='text/css' media="screen" />
<style>
.error {color: #FF0000;}
</style>

</head>

<body>

<h2>Password reset</h2>
<form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">

<?php

// Tokens directory path
$tokendir = "./tokens/";
$requeststore = "./requeststore/";

$token = $_GET["token"];
$pass = $passagain = $username = "";
$passerr = $passagainerr = " ";

if (file_exists($tokendir.$token)) {
    $username = file_get_contents($tokendir.$token);
    echo "<input type=hidden name=username value=".$username.">";
    $passmatch = false;
    $passstrong = false;
    
    /*
    if ($username == "") {
        echo "<script type='text/javascript'>
                alert('Invalid link');
                window.location.href='http://www2.cs.binghamton.edu/~jyao6/';
              </script>";
    }
    */
    
    if (isset($_POST["pass"])) {
        $pass = $_POST["pass"];
        $passagain = $_POST["passagain"];
        $username = $_POST["username"];
    
        if ($pass != $passagain) {
            $passagainerr = "* Passwords do not match";
        } else {
            $passmatch = true;
        }
        
        // TODO: Check password strength
        /* pass requirements:
        min 9 char
        3 of 4 char classes (lower, upper, numbers, specialchars)*/
        if (strlen($pass) >= 9) {
            // TODO: check here
            $passstrong = true;
        } else {
            $passerr = "* Password length must be at least 9 and have 3 of (a-z, A-Z, 0-9, special)";
        }
        
        // file_put_contents($requeststore.$username, "hi");
        
        if ($passmatch && $passstrong) {
            // Update password here
            $publickey = openssl_pkey_get_public("file://public_key.pem");
            openssl_public_encrypt($pass, $encryptedpassword, $publickey);
            file_put_contents($requeststore.$username, $encryptedpassword);

            // To Decrypt:
            $privatekey = openssl_pkey_get_private("file://private_key.pem");
            openssl_private_decrypt($encryptedpassword, $decryptedpassword, $privatekey);
            
            
            $ldaphost = "ldaps://ldap.cs.binghamton.edu";
            $ldapconn = ldap_connect($ldaphost)
                    or die("Could not connect to ".$ldaphost); 
            $dn = "ou=People,dc=cs,dc=binghamton,dc=edu";
            $sr = ldap_search($ldapconn, $dn, "uid=jyao6");
            $info = ldap_get_entries($ldapconn, $sr);
            
            // Should only have 1 user
            for ($i=0; $i<$info["count"]; $i++)
            {
                // to show the attribute displayName (note the case!)
                echo $info[$i]["mail"][0];
                echo $info[$i]["mail"][1];
            }
           
            echo "<script type='text/javascript'>
                    alert('Password updated to \"".$pass."\"');
			        window.location.href='http://www2.cs.binghamton.edu/~jyao6/';
                  </script>";
        }   
    }   
}

?>

  New Password: <input type="password" name="pass">
  <span class="error"><?php echo $passerr;?></span>
  <br><br>
  New password again: <input type="password" name="passagain">
  <span class="error"><?php echo $passagainerr;?></span>
  <br><br>
  <input type="submit" name="submit" value="Submit">
</form>

</body>
</html>

