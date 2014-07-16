<?php

ini_set('display_errors', true);

require "src/Encrypt.php";
require "src/EncryptException.php";

class Demo {
	public $not_secret, $secret;
}

foreach(array("Base64" => 0, "Binary" => OPENSSL_RAW_DATA) as $title => $openssl_option){
	echo "<h2>{$title}</h2>";
	$obj = new Demo();
	
	$conf = array(
		"encrypted" => array("secret"), 
		"openssl_options" => $openssl_option
	);
	$enc = new Oonix\Encrypt($obj, "SECRET_KEY_6X2tjYipm4Wr8Sl0", "AES-128-CBC", $conf);

	foreach(array("not_secret" => "public", "secret" => "private") as $key => $data){
		$enc->$key = "some {$data} data";
		var_dump($obj->$key);
		var_dump($enc->$key);
	}
}
?>
