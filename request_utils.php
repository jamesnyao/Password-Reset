<?php

function new_request($username, $encrypted_pass) {
    $reqs_path = "/home/jyao6/reqs/";
    $lastnum_path = $reqs_path."lastnum"; // reqs/pending
    $pending_path = $reqs_path."pending/";

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

?>
