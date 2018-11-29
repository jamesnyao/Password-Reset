<?php

include "/home/public_html/utils/database.php";

$handle = fopen ("php://stdin","r");
$userid = trim(fgets($handle));

$conn = db_create_connection();

$sql = "SELECT DECODE(`passwd`, ".db_get_secret().") AS `passwd` FROM `requests` WHERE `username` = '".$userid."'";
$pass = $conn->query($sql);
$sql = "DELETE FROM `requests` WHERE `username` = '".$userid."'";
$conn->query($sql);

$conn->close();
print($pass);

?>
