<?php

$handle = fopen ("php://stdin","r");
$line = fgets($handle);
$privatekey = openssl_pkey_get_private("file://private_key.pem");
openssl_private_decrypt($line, $decryptedpassword, $privatekey);
print($decryptedpassword);

?>
