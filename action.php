<html>
<body>

<?php

require_once "./lib/random.php";

// Tokens directory path
$tokendir = "./tokens/";

$username = $_GET["username"];
$bnum = $_GET["bnum"];

echo "Username is ".$username."<br>";
echo "BNumber is ".$bnum."<br>";

// TODO: Check if bnumber and username is correct.
if ($bnum == "123") {

    // Generate Token
    $token = "";
    do {
        $length = 64; // Choose length of token
        $token = "";
        $codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $codeAlphabet .= "abcdefghijklmnopqrstuvwxyz";
        $codeAlphabet .= "0123456789";
        $max = strlen($codeAlphabet);

        for ($i = 0; $i < $length; $i++) {
            $token .= $codeAlphabet[random_int(0, $max-1)];
        }

    } while(file_exists($tokendir.$token)); 

    file_put_contents($tokendir.$token, $username);

    // Email
    echo "www2.cs.binghamton.edu/~jyao6/return.php?token=".$token."<br>";
    
    $msg = "You have requested to change your CS LDAP password.\nClick this link: www2.cs.binghamton.edu/~jyao6/return.php?token=".$token."\n";

    $header = "From: sysadmin@cs.binghamton.edu";

    // TODO: Lookup correct email address
    $emailaddr = $username."@binghamton.edu";

    // TODO: fix mail
    mail($emailaddr, "CS LDAP password reset", $msg, $header);

    echo "Email sent to ".$emailaddr;

// bnumber not right
} else {

    echo "Incorrect B-Number for this user<br>";
    
}

?>

</body>

</html>


