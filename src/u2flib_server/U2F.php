<?php

// Copyright (c) 2014 Yubico AB
// All rightes reserved.

namespace u2flib_server;

class U2F {

  private static $version = "U2F_V2";
  private $appId;

  public function __construct($appId) {
    $this->appId = $appId;
  }

  public function getRegisterData($keyHandles = Null) {

    $challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32));
    $request = new RegisterRequest(U2F::$version, $challenge, $this->appId);
    return json_encode($request);
  }

  public function doRegister($challenge, $response) {

  }

  public function getAuthenticateData($keyHandles) {

  }

  public function doAuthenticate() {

  }

  private static function base64u_encode($data) {
    return trim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  private static function base64u_decode($data) {
    return base64_decode(strtr($data, '-_', '+/'));
  }
}

class RegisterRequest {
  public $version;
  public $challenge;
  public $appId;

  public function __construct($version, $challenge, $appId) {
    $this->version = $version;
    $this->challenge = $challenge;
    $this->appId = $appId;
  }
}

?>
