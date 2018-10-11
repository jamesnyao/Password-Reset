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
  <div id='page-heading'>
	<h1 class='page-heading-title'>CS Department at Binghamton University<br />System Administration Support Interface</h1>
	<div class='page-heading-description'>
		<h2 class='page-heading-topic'>System Administration Support Page</h2>
		<p class='page-heading-description'>&nbsp;</p>
	</div>
	<hr />
  </div>

  <div class='information-block'>
    <h2>Password reset</h2>
    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">

<?php

include "utils/request_utils.php";

$token = $_GET["token"];
$pass = $passagain = $username = "";
$passerr = $passagainerr = " ";

if (file_exists($tokensdir.$token))
{
    $username = file_get_contents($tokensdir.$token);
    echo "<input type=hidden name=username value=".$username.">";
    echo "<input type=hidden name=passok value=".$passok.">";
    $passok = "";
    
    if (isset($_POST["pass"]))
    {
        $pass = $_POST["pass"];
        $passagain = $_POST["passagain"];
        $username = $_POST["username"];
    
        if ($pass != $passagain)
        {
            $passagainerr = "* Passwords do not match";
        }
        else
        {
            $passok = "match";
        }
        
        // Check password strength
        $hold = check_pass_strength($pass);
        
        // Password good
        if ($hold == "strong" && $passok == "match")
        {           
            // Generate pending request with encrypted password
            new_request($username, encrypt_pass($pass, $publickey_file));
           
            echo "<script type='text/javascript'>
                    alert('Password successfully updated. Allow up to 10 minutes for the new password to be set.');
                    window.location.href='http://www2.cs.binghamton.edu/~jyao6/';
                  </script>";
        }
        
        // Password not good
        else
        {
            $passerr = $hold;
        }
    }   
}

?>

      <font size="4">&emsp;Enter new password: <input style="font-size:15px;" type="password" name="pass">
      <span class="error"><?php echo $passerr;?></span>
      <br><br>
      <font size="4">&emsp;Enter new password again: <input style="font-size:15px;" type="password" name="passagain">
      <span class="error"><?php echo $passagainerr;?></span>
      <br><br>
      <input type="submit" name="submit" value="Submit">
    </form>
  </div>

</body>
</html>

