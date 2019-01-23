<?php

function db_create_connection()
{
    $servername = "";
    $username = "";
    $password = "";
    $dbname = "";
    
    return new mysqli($servername, $username, $password, $dbname);
}

function db_get_secret()
{
    return "";
}

?>
