<?php

// Copyright (c) 2014 Yubico AB
// All rightes reserved.

namespace u2flib_server;

use \File_X509;
use \File_ASN1;
use \phpecc\PublicKey;
use \phpecc\NISTcurve;
use \phpecc\Signature;
use \phpecc\Point;

define ('USE_EXT', 'GMP');
define ('U2F_VERSION', 'U2F_V2');

class U2F {
  private $appId;

  public function __construct($appId) {
    $this->appId = $appId;
  }

  public function getRegisterData($keyHandles = Null) {
    $challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32));
    $request = new RegisterRequest($challenge, $this->appId);
    return json_encode($request, JSON_UNESCAPED_SLASHES);
  }

  public function doRegister($request, $data) {
    $response = json_decode($data);
    $rawReg =  U2F::base64u_decode($response->registrationData);
    $regData = unpack('C*', $rawReg);
    $clientData = U2F::base64u_decode($response->clientData);
    $req = json_decode($request);
    $cli = json_decode($clientData);

    if($cli->challenge !== $req->challenge) {
      return null;
    }

    $registration = new Registration();
    $registration->publicKey = bin2hex(substr($rawReg, 1, 65));
    $khLen = $regData[67];
    $registration->keyHandle = bin2hex(substr($rawReg, 67, $khLen));

    $certLen = 4;
    $certLen += ($regData[67 + $khLen + 3] << 8);
    $certLen += $regData[67 + $khLen + 4];

    $x509 = new File_X509();
    $registration->certificate = bin2hex(substr($rawReg, 67 + $khLen, $certLen));
    $cert = $x509->loadX509(hex2bin($registration->certificate));
    $rawKey = base64_decode($cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']);
    $signing_key = U2F::pubkey_decode(substr(bin2hex($rawKey), 2));
    $signature = substr($rawReg, 67 + $khLen + $certLen);
    $sig = U2F::sig_decode($signature);

    $sha256 = hash_init('sha256');
    hash_update($sha256, chr(0));
    hash_update($sha256, hash('sha256', $req->appId, true));
    hash_update($sha256, hash('sha256', $clientData, true));
    hash_update($sha256, hex2bin($registration->keyHandle));
    hash_update($sha256, hex2bin($registration->publicKey));
    $hash = hash_final($sha256);

    if($signing_key->verifies(gmp_strval(gmp_init($hash, 16), 10), $sig) == true) {
      return json_encode($registration);
    } else {
      return null;
    }
  }

  public function getAuthenticateData($registrations) {
    $sigs = [];
    foreach ($registrations as $registration) {
      $reg = json_decode($registration);
      $sig = new SignRequest();
      $sig->appId = $this->appId;
      $sig->keyHandle = U2F::base64u_encode(hex2bin($reg->keyHandle));
      $sig->challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32));
      $sigs[] = json_encode($sig, JSON_UNESCAPED_SLASHES);
    }
    return $sigs;
  }

  public function doAuthenticate() {

  }

  private static function base64u_encode($data) {
    return trim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  private static function base64u_decode($data) {
    return base64_decode(strtr($data, '-_', '+/'));
  }

  private static function sig_decode($signature) {
    $asn1 = new File_ASN1();
    $r = $asn1->decodeBER($signature)[0]['content'][0]['content'];
    $s = $asn1->decodeBER($signature)[0]['content'][1]['content'];
    $gmpR = gmp_strval(gmp_init($r->toHex(), 16), 10);
    $gmpS = gmp_strval(gmp_init($s->toHex(), 16), 10);
    return new Signature($gmpR, $gmpS);
  }

  private static function pubkey_decode($key) {
    if(substr($key, 0, 2) != "04") {
      throw new ErrorException("Key must be a HEX string of a public ECC key");
    }
    $curve = NISTcurve::generator_256();
    $x = gmp_strval(gmp_init(substr($key, 2, 64), 16), 10);
    $y = gmp_strval(gmp_init(substr($key, 2+64, 64), 16), 10);
    return new PublicKey($curve, new Point($curve->getCurve(), $x, $y));
  }
}

class RegisterRequest {
  public $version = U2F_VERSION;
  public $challenge;
  public $appId;

  public function __construct($challenge, $appId) {
    $this->challenge = $challenge;
    $this->appId = $appId;
  }
}

class SignRequest {
  public $version = U2F_VERSION;
  public $challenge;
  public $keyHandle;
  public $appId;
}

class Registration {
  public $keyHandle;
  public $publicKey;
  public $certificate;
}

?>
