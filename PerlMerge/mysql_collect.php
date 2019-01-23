<?php

include "/home/public_html/utils/database.php";

$conn = db_create_connection();

$sql = "SELECT * FROM requests";
$result = $conn->query($sql);

$userid = "test";
while ($row = $result->fetch_assoc())
{
    if ($userid == "test") $userid = $row["username"];
    else $userid += ",".$row["username"];
}
$conn->close();
print($userid);

?>
