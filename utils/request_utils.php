<?php

require_once "lib/random.php";
include "utils/database.php";

// Get bmail info from $ldapinfo (from ldap_search())
function ldap_get_bmail($ldapinfo)
{
    for ($i = 0; $i < $ldapinfo[0]["mail"]["count"]; $i++)
    {
        if (strpos($ldapinfo[0]["mail"][$i], "@binghamton.edu") !== false)
        {
            return $ldapinfo[0]["mail"][$i];
        }
    }
    return "None";
}

// Get bnumber infor from $ldapinfo (from ldap_search())
function ldap_get_bnum($ldapinfo)
{
    return $ldapinfo[0]["bnumber"][0];
}

// Generate a new token; returns empty string if connection fails
function generate_token($username)
{
    // Create connection
    $conn = db_create_connection();
    
    // Check connection
    if ($conn->connect_error)
    {
        die("Connection failed: ".$conn->connect_error);
        return "";
    }
    
    $token = "";
    do
    {
        $length = 64; // Choose length of token
        $token = "";
        $codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $codeAlphabet .= "abcdefghijklmnopqrstuvwxyz";
        $codeAlphabet .= "0123456789";
        $max = strlen($codeAlphabet);
        for ($i = 0; $i < $length; $i++)
        {
            $token .= $codeAlphabet[random_int(0, $max-1)];
        }
        $sql = "SELECT * FROM `tokens` WHERE `token` = '".$token."'";
        $result = $conn->query($sql);
    }
    while($result->num_rows > 0); 

    $sql = "DELETE FROM tokens WHERE timestamp < (CURDATE() - INTERVAL 30 MINUTE)";
    $conn->query($sql);
    
    $sql = "INSERT INTO `tokens` (`username`, `token`) VALUES ('".$username."', '".$token."')";
    if (!$conn->query($sql))
    {
        $token = "";
    }
    $conn->close();
    return $token;
}

// Checks if $pass meets password requirements:
// 9 to 20 string length, 3 of 4 char classes (upper, lower, numbers, specialchars)
function check_pass_strength($pass)
{
    if (strlen($pass) >= 9 && strlen($pass) <= 20)
    {
        $uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $lowers = "abcdefghijklmnopqrstuvwxyz";
        $numbers = "0123456789";
        $specials = " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~";
        $uppersmatch = $lowersmatch = $numbersmatch = $specialsmatch = 0;
        for ($i = 0; $i < strlen($pass); $i++)
        {
            if (strpos($uppers, $pass{$i}) !== false)
            {
                $uppersmatch = 1;
            }
            elseif (strpos($lowers, $pass{$i}) !== false)
            {
                $lowersmatch = 1;
            }
            elseif (strpos($numbers, $pass{$i}) !== false)
            {
                $numbersmatch = 1;
            }
            elseif (strpos($specials, $pass{$i}) !== false)
            {
                $specialsmatch = 1;
            }
            else
            {
                return "* Password character not allowed";
            }
            if ($uppersmatch + $lowersmatch + $numbersmatch + $specialsmatch >= 3)
            {
                return "strong";
            }
        }
    }
    return "* Password length must be at least 9 and have 3 of (A-Z, a-z, 0-9, special)";
}

/*
// Generate a new request to reqs/pending and increments lastnum
function new_request($username, $encrypted_pass)
{
    $reqs_path = "/home/jyao6/reqs/";
    $lastnum_path = $reqs_path."lastnum";
    $pending_path = $reqs_path."pending/";  // reqs/pending

    $idnum = 1;
    if (file_exists($lastnum_path)) {
        $idnum = intval(file_get_contents($lastnum_path));
        $idnum++;
    }
    file_put_contents($lastnum_path, (string) $idnum, LOCK_EX);
    
    $req_msg =
        "request_by\t".$username."\n"
        ."reset_password_encrypted\t".$username."\n"
        ."-----start-----\n"
        .$encrypted_pass."\n"
        ."-----end-----\n";
    file_put_contents($pending_path.((string) $idnum).".req", $req_msg);
}
*/

?>
