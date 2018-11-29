<?php

include "/home/public_html/utils/database.php";

$conn = db_create_connection();

$sql = "SELECT * FROM requests";
$result = $conn->query($sql);

$userid = "";
if ($row = $result->fetch_assoc())
{
    $userid = $row["username"];
}
$conn->close();
print($userid);

?>
