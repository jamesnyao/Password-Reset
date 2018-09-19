<html>
<body>

<?php

require_once "./lib/random.php";

// Tokens directory path
$tokendir = "./tokens/";

$username = $_GET["username"];
$bnum = $_GET["bnum"];

// Lookup correct email address
$emailaddr = "";
$checkbnum = "123";
$ldaphost = "ldaps://ldap.cs.binghamton.edu";
$ldapconn = ldap_connect($ldaphost)
        or die("Could not connect to ".$ldaphost); 
$dn = "ou=People,dc=cs,dc=binghamton,dc=edu";
$sr = ldap_search($ldapconn, $dn, "uid=jyao6");
$info = ldap_get_entries($ldapconn, $sr);
for ($i = 0; $i < $info[0]["mail"]["count"]; $i++) {
    if (strpos($info[0]["mail"][$i], "@binghamton.edu") !== false) {
        $emailaddr = $info[0]["mail"][$i];
        break;
    }
}
// TODO: Bnumber lookup
// $checkbnum = $info[0]["bnumber"][0];

// Check if bnumber and username is correct.
if ($bnum == $checkbnum) {

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

    // Create token file
    file_put_contents($tokendir.$token, $username);

    // Email    
    $msg = "You have requested to change your CS LDAP password.\n
            Click this link: www2.cs.binghamton.edu/~jyao6/return.php?token="
            .$token."\n";
    $header = "From: sysadmin@cs.binghamton.edu";
    mail($emailaddr, "CS LDAP password reset", $msg, $header);
    echo "Email with reset link sent to ".$emailaddr;

// Bnumber not correct
} else {
    echo "Incorrect B-Number for this user<br>";
}

?>

</body>
</html>
