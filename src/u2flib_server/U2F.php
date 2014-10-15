<?php

 /* Copyright (c) 2014 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace u2flib_server;

use \File_X509;
use \File_ASN1;
use \Mdanter\Ecc\EccFactory;
use \Mdanter\Ecc\PublicKey;
use \Mdanter\Ecc\Signature;
use \Mdanter\Ecc\Point;


const U2F_VERSION = "U2F_V2";

const ERR_NO_MATCHING_REQUEST = 1;
const ERR_NO_MATCHING_REGISTRATION = 2;
const ERR_AUTHENTICATION_FAILURE = 3;
const ERR_UNMATCHED_CHALLENGE = 4;
const ERR_ATTESTATION_SIGNATURE = 5;
const ERR_ATTESTATION_VERIFICATION = 6;

class U2F {
  private $appId;
  private $attestDir;

  public function __construct($appId, $attestDir = null) {
    //ModuleConfig::useGmp();
    $this->appId = $appId;
    $this->attestDir = $attestDir;
  }

  public function getRegisterData($keyHandles = array()) {
    $challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32));
    $request = new RegisterRequest($challenge, $this->appId);
    $signs = $this->getAuthenticateData($keyHandles);
    return array(json_encode($request), $signs);
  }

  public function doRegister($request, $data, $include_cert = true) {
    $response = json_decode($data);
    $rawReg =  U2F::base64u_decode($response->registrationData);
    $regData = unpack('C*', $rawReg);
    $clientData = U2F::base64u_decode($response->clientData);
    $req = json_decode($request);
    $cli = json_decode($clientData);

    if($cli->challenge !== $req->challenge) {
      $error = new Error(ERR_UNMATCHED_CHALLENGE, "Registration challenge does not match");
    }

    $registration = new Registration();
    $pubKey = substr($rawReg, 1, 65);
    $registration->publicKey = base64_encode($pubKey);
    $khLen = $regData[67];
    $kh = substr($rawReg, 67, $khLen);
    $registration->keyHandle = U2F::base64u_encode($kh);

    $certLen = 4;
    $certLen += ($regData[67 + $khLen + 3] << 8);
    $certLen += $regData[67 + $khLen + 4];

    $rawCert = substr($rawReg, 67 + $khLen, $certLen);
    if($include_cert) {
      $registration->certificate = base64_encode($rawCert);
    }
    $x509 = $this->setup_certs();
    $cert = $x509->loadX509($rawCert);
    if($this->attestDir) {
      if(!$x509->validateSignature($cert)) {
        $error = new Error(ERR_ATTESTATION_VERIFICATION, "Attestation certificate can not be validated");
        return json_encode($error);
        /* XXX: validateDate uses platform time_t to represent time, 
         * this breaks with long validity periods and 32-bit platforms.
      } else if (!$x509->validateDate()) {
        return null; */
      }
    }

    $encodedKey = $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
    $rawKey = base64_decode($encodedKey);
    $signing_key = U2F::pubkey_decode(substr(bin2hex($rawKey), 2));
    $signature = substr($rawReg, 67 + $khLen + $certLen);
    $sig = U2F::sig_decode($signature);

    $sha256 = hash_init('sha256');
    hash_update($sha256, chr(0));
    hash_update($sha256, hash('sha256', $req->appId, true));
    hash_update($sha256, hash('sha256', $clientData, true));
    hash_update($sha256, $kh);
    hash_update($sha256, $pubKey);
    $hash = hash_final($sha256);

    if($signing_key->verifies(gmp_strval(gmp_init($hash, 16), 10), $sig) == true) {
      $ret = $registration;
    } else {
      $ret = new Error(ERR_ATTESTATION_SIGNATURE, "Attestation signature does not match");
    }
    return json_encode($ret);
  }

  public function getAuthenticateData($registrations) {
    $sigs = array();
    foreach ($registrations as $registration) {
      $reg = json_decode($registration);
      $sig = new SignRequest();
      $sig->appId = $this->appId;
      $sig->keyHandle = $reg->keyHandle;
      $sig->challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32));
      $sigs[] = $sig;
    }
    return json_encode($sigs);
  }

  public function doAuthenticate($requests, $registrations, $data) {
    $response = json_decode($data);
    $req = null;
    $reg = null;
    foreach ($requests as $request) {
      $req = json_decode($request);
      if($req->keyHandle === $response->keyHandle) {
        break;
      }
      $req = null;
    }
    if($req === null) {
      $error = new Error(ERR_NO_MATCHING_REQUEST, "No matching request found");
      return json_encode($error);
    }
    foreach ($registrations as $registration) {
      $reg = json_decode($registration);
      if($reg->keyHandle === $response->keyHandle) {
        break;
      }
      $reg = null;
    }
    if($reg === null) {
      $error = new Error(ERR_NO_MATCHING_REGISTRATION, "No matching registration found");
      return json_encode($error);
    }

    $key = U2F::pubkey_decode(bin2hex(U2F::base64u_decode($reg->publicKey)));
    $signData = U2F::base64u_decode($response->signatureData);
    $clientData = U2f::base64u_decode($response->clientData);
    $sha256 = hash_init('sha256');
    hash_update($sha256, hash('sha256', $req->appId, true));
    hash_update($sha256, substr($signData, 0, 5));
    hash_update($sha256, hash('sha256', $clientData, true));
    $hash = hash_final($sha256);
    $sig = U2f::sig_decode(substr($signData, 5));
    if($key->verifies(gmp_strval(gmp_init($hash, 16), 10), $sig) === true) {
      $ctr = unpack("C*", substr($signData, 1, 4));
      $ret = new Authentication(($ctr[1] << 24) + ($ctr[2] << 16) + ($ctr[3] << 8) + ($ctr[4]));
    } else {
      $ret = new Error(ERR_AUTHENTICATION_FAILURE, "Authentication failed");
    }
    return json_encode($ret);
  }

  private function setup_certs() {
    $x509 = new File_X509();
    $dir = $this->attestDir;
    if ($dir && $handle = opendir($dir)) {
      while(false !== ($entry = readdir($handle))) {
        if($entry !== "." && $entry !== "..") {
          $contents = file_get_contents("$dir/$entry");
          $x509->loadCA($contents);
        }
      }
      closedir($handle);
    }
    return $x509;
  }

  private static function base64u_encode($data) {
    return trim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  private static function base64u_decode($data) {
    return base64_decode(strtr($data, '-_', '+/'));
  }

  private static function sig_decode($signature) {
    $asn1 = new File_ASN1();
    $sig = $asn1->decodeBER($signature);
    $r = $sig[0]['content'][0]['content'];
    $s = $sig[0]['content'][1]['content'];
    $gmpR = gmp_strval(gmp_init($r->toHex(), 16), 10);
    $gmpS = gmp_strval(gmp_init($s->toHex(), 16), 10);
    return new Signature($gmpR, $gmpS);
  }

  private static function pubkey_decode($key) {
    if(substr($key, 0, 2) != "04") {
      throw new \Exception("Key must be a HEX string of a public ECC key");
    }
    $curve = EccFactory::getNistCurves()->generator256();
    $x = gmp_strval(gmp_init(substr($key, 2, 64), 16), 10);
    $y = gmp_strval(gmp_init(substr($key, 2+64, 64), 16), 10);
    $adapter = EccFactory::getAdapter();
    return new PublicKey($curve, new Point($curve->getCurve(), $x, $y, null, $adapter), $adapter);
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

class Authentication {
  public $counter;

  public function __construct($counter) {
    $this->counter = $counter;
  }
}

class Error {
  public $errorCode;
  public $errorMessage;

  public function __construct($code, $message) {
    $this->errorCode = $code;
    $this->errorMessage = $message;
  }
}

?>
