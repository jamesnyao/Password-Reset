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

if (!isset($_POST["pass"]))
{
    // Create connection
    $conn = db_create_connection();

    // Check connection
    if ($conn->connect_error)
    {
        die("Connection failed: ".$conn->connect_error);
    }

    $sql = "SELECT * FROM tokens";
    $result = $conn->query($sql);

    while ($row = $result->fetch_assoc())
    {
        if ($row["token"] == $token)
        {
            $username = $row["username"];
            $sql = "DELETE FROM `tokens` WHERE `token`='".$token."'";
            $result = $conn->query($sql);
            break;
        }
    }
    $conn->close();
    
    if ($username == "")
    {
        echo "<script type='text/javascript'>
                alert('Invalid link. Please request a new password change email.');
                window.location.href='http://www2.cs.binghamton.edu/~jyao6/';
              </script>";
    }
    
    echo "<input type=hidden name=username value=".$username.">";
}
else
{   
    $pass = $_POST["pass"];
    $passagain = $_POST["passagain"];
    $username = $_POST["username"];
    $passok = "";

    if ($pass != $passagain)
    {
        $passagainerr = "* Passwords do not match";
    }
    else
    {
        $passok = "match";
    }
    
    // Check password strength
    $strengthcheck = check_pass_strength($pass);
    
    // Password good
    if ($strengthcheck == "strong" && $passok == "match")
    {
        // Create connection
        $conn = db_create_connection();

        // Check connection
        if ($conn->connect_error)
        {
            die("Connection failed: ".$conn->connect_error);
        }
        
        $sql = "INSERT INTO `requests` (`username`, `passwd`) VALUES ('".$username."', ENCODE('".$pass."', '".db_get_secret()."'))";
        
        if ($conn->query($sql))
        {
            echo "<script type='text/javascript'>
                    alert('Password successfully updated. Allow up to 5 minutes for the new password to be set.')
                  </script>";
        }
        else
        {
            echo "<script type='text/javascript'>
                    alert('A database error occurred. Please try again later.')
                  </script>";
        }
        $conn->close();
        echo "<script type='text/javascript'>
                window.location.href='http://www2.cs.binghamton.edu/~jyao6/'
              </script>";
    }
    
    // Password not good
    else
    {
        $passerr = $strengthcheck;
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

