<?php

$data = file_get_contents("http://admin:admin@127.0.0.1/create?user=test&image=dockeraccess-base");
$obj = json_decode($data);
if ($obj !== NULL) {
    var_dump($obj);
    $socket = $obj->instance_path;
    $password = $obj->instance_password;
    $host = $obj->host_name;
    $port = $obj->host_port;
    echo $host . "/vnc.html?resize=scale&autoconnect=1&host=" . $host . "&port=" . $port . "&password=" . $password . "&path=" . $socket;
} else {
    echo $data;
}

