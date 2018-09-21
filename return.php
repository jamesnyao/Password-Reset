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
$tokendir = "./tokens/";    // /home/jyao6/reqs/tokens
$requeststore = "/home/jyao6/Desktop/";     // create into reqs/pending

$token = $_GET["token"];
$pass = $passagain = $username = "";
$passerr = $passagainerr = " ";

if (file_exists($tokendir.$token)) {
    $username = "jyao6";//file_get_contents($tokendir.$token);
    echo "<input type=hidden name=username value=".$username.">";
    echo "<input type=hidden name=passok value=".$passok.">";
    $passok = "0";
    
    if (isset($_POST["pass"])) {
        $pass = $_POST["pass"];
        $passagain = $_POST["passagain"];
        $username = $_POST["username"];
    
        if ($pass != $passagain) {
            $passagainerr = "* Passwords do not match";
        } else {
            $passok = "1";
        }
        
        // Password requirements:
        // 9 to 20 string length, 3 of 4 char classes (upper, lower, numbers, specialchars)
        if (strlen($pass) >= 9 && strlen($pass) <= 20) {
            $uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            $lowers = "abcdefghijklmnopqrstuvwxyz";
            $numbers = "0123456789";
            $specials = " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~";
            $uppersmatch = $lowersmatch = $numbersmatch = $specialsmatch = 0;
            for ($i = 0; $i < strlen($pass); $i++) {
                if (strpos($uppers, $pass{$i}) !== false) {
                    $uppersmatch = 1;
                } elseif (strpos($lowers, $pass{$i}) !== false) {
                    $lowersmatch = 1;
                } elseif (strpos($numbers, $pass{$i}) !== false) {
                    $numbersmatch = 1;
                } elseif (strpos($specials, $pass{$i}) !== false) {
                    $specialsmatch = 1;
                } else {
                    $passerr = "* Password character not allowed";
                    break;
                }
                if ($uppersmatch + $lowersmatch + $numbersmatch + $specialsmatch >= 3) {
                    if ($passok == "1") $passok = "2";
                    break;
                }
            }
        } else {
            $passerr = "* Password length must be at least 9 and have 3 of (A-Z, a-z, 0-9, special)";
        }
        
        if ($passok == "2") {
            // Update password here
            $publickey = openssl_pkey_get_public("file://public_key.pem");
            openssl_public_encrypt($pass, $encryptedpassword, $publickey);
            //file_put_contents($requeststore.$username, $encryptedpassword);
            
            // TODO: Call request_utils or write new request_utils.php to generate
            // pending request/increment $idnum

            // To Decrypt:
            $privatekey = openssl_pkey_get_private("file://private_key.pem");
            openssl_private_decrypt($encryptedpassword, $decryptedpassword, $privatekey);
            
            // TODO: Update password here
           
            echo "<script type='text/javascript'>
                    alert('Password updated to \"".$pass."\"');
                    
                  </script>";
        } else {
            echo "<script type='text/javascript'>
                    alert('passok: \"".$passok."\"');
                  </script>";
        }
    }   
}
//window.location.href='http://www2.cs.binghamton.edu/~jyao6/';
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

