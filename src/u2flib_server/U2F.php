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

/** Constant for the version of the u2f protocol */
const U2F_VERSION = "U2F_V2";

/** Error for the authentication message not matching any outstanding
 * authentication request */
const ERR_NO_MATCHING_REQUEST = 1;
/** Error for the authentication message not matching any registration */
const ERR_NO_MATCHING_REGISTRATION = 2;
/** Error for the signature on the authentication message not verifying with
 * the correct key */
const ERR_AUTHENTICATION_FAILURE = 3;
/** Error for the challenge in the registration message not matching the
 * registration challenge */
const ERR_UNMATCHED_CHALLENGE = 4;
/** Error for the attestation signature on the registration message not
 * verifying */
const ERR_ATTESTATION_SIGNATURE = 5;
/** Error for the attestation verification not verifying */
const ERR_ATTESTATION_VERIFICATION = 6;
/** Error for not getting good random from the system */
const ERR_BAD_RANDOM = 7;
/** Error when the counter is lower than expected */
const ERR_COUNTER_TO_LOW = 8;
/** Error decoding public key */
const ERR_PUBKEY_DECODE = 9;

/** @internal */
const PUBKEY_LEN = 65;

class U2F {
  private $appId;
  private $attestDir;

  /**
   * @param string Application id for the running application
   * @param string Directory where trusted attestation roots may be found
   */
  public function __construct($appId, $attestDir = null) {
    $this->appId = $appId;
    $this->attestDir = $attestDir;
  }

  /**
   * Called to get a registration request to send to a user.
   * Returns an array of one registration request and a array of sign requests.
   * @param array $keyhandles optional list of current key handles for this
   * user, to prevent the user from registering the same authenticator serveral
   * times.
   * @return array|Error An array of two elements, the first containing a
   * RegisterRequest the second being an array of SignRequest
   */
  public function getRegisterData($keyHandles = array()) {
    $challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32, $crypto_strong));
    if($crypto_strong != true) {
      $error = new Error(ERR_BAD_RANDOM, "Unable to obtain a good source of randomness");
      return $error;
    }
    $request = new RegisterRequest($challenge, $this->appId);
    $signs = $this->getAuthenticateData($keyHandles);
    return array($request, $signs);
  }

  /**
   * Called to verify and unpack a registration message.
   * @param RegisterRequest request this is a reply to
   * @param RegisterResponse response from a user
   * @param bool set to true if the attestation certificate should be
   * included in the returned Registration object
   * @return Registration|Error
   */
  public function doRegister($request, $response, $include_cert = true) {
    $rawReg =  U2F::base64u_decode($response->registrationData);
    $regData = array_values(unpack('C*', $rawReg));
    $clientData = U2F::base64u_decode($response->clientData);
    $cli = json_decode($clientData);

    if($cli->challenge !== $request->challenge) {
      return new Error(ERR_UNMATCHED_CHALLENGE, "Registration challenge does not match");
    }

    $registration = new Registration();
    $offs = 1;
    $pubKey = substr($rawReg, $offs, PUBKEY_LEN);
    $offs += PUBKEY_LEN;
    // decode the pubKey to make sure it's good
    $tmpkey = U2F::pubkey_decode(bin2hex($pubKey));
    if($tmpkey == null) {
      return new Error(ERR_PUBKEY_DECODE, "Decoding of public key failed");
    }
    $registration->publicKey = base64_encode($pubKey);
    $khLen = $regData[$offs++];
    $kh = substr($rawReg, $offs, $khLen);
    $offs += $khLen;
    $registration->keyHandle = U2F::base64u_encode($kh);

    // length of certificate is stored in byte 3 and 4 (excluding the first 4 bytes)
    $certLen = 4;
    $certLen += ($regData[$offs + 2] << 8);
    $certLen += $regData[$offs + 3];

    $rawCert = substr($rawReg, $offs, $certLen);
    $offs += $certLen;
    if($include_cert) {
      $registration->certificate = base64_encode($rawCert);
    }
    $x509 = $this->setup_certs();
    $cert = $x509->loadX509($rawCert);
    if($this->attestDir) {
      if(!$x509->validateSignature($cert)) {
        return new Error(ERR_ATTESTATION_VERIFICATION, "Attestation certificate can not be validated");
        /* XXX: validateDate uses platform time_t to represent time, 
         * this breaks with long validity periods and 32-bit platforms.
      } else if (!$x509->validateDate()) {
        return null; */
      }
    }

    $encodedKey = $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
    $rawKey = base64_decode($encodedKey);
    $signing_key = U2F::pubkey_decode(substr(bin2hex($rawKey), 2));
    if($signing_key == null) {
      return new Error(ERR_PUBKEY_DECODE, "Decoding of public key failed");
    }
    $signature = substr($rawReg, $offs);
    $sig = U2F::sig_decode($signature);

    $sha256 = hash_init('sha256');
    hash_update($sha256, chr(0));
    hash_update($sha256, hash('sha256', $request->appId, true));
    hash_update($sha256, hash('sha256', $clientData, true));
    hash_update($sha256, $kh);
    hash_update($sha256, $pubKey);
    $hash = hash_final($sha256);

    if($signing_key->verifies(gmp_strval(gmp_init($hash, 16), 10), $sig) == true) {
      return $registration;
    } else {
      return new Error(ERR_ATTESTATION_SIGNATURE, "Attestation signature does not match");
    }
  }

  /**
   * Called to get an authentication request.
   * @param array An array of the registrations to create authentication requests for.
   * @return array|Error An array of SignRequest
   */
  public function getAuthenticateData($registrations) {
    $sigs = array();
    foreach ($registrations as $reg) {
      $sig = new SignRequest();
      $sig->appId = $this->appId;
      $sig->keyHandle = $reg->keyHandle;
      $sig->challenge = U2F::base64u_encode(openssl_random_pseudo_bytes(32, $crypto_strong));
      if($crypto_strong != true) {
        return new Error(ERR_BAD_RANDOM, "Unable to obtain a good source of randomness");
      }
      $sigs[] = $sig;
    }
    return $sigs;
  }

  /**
   * Called to verify an authentication response
   * @param array An array of outstanding authentication requests
   * @param array An array of current registrations
   * @param SignResponse A response from the authenticator
   * @return Registration|Error
   */
  public function doAuthenticate($requests, $registrations, $response) {
    $req = null;
    $reg = null;
    foreach ($requests as $req) {
      if($req->keyHandle === $response->keyHandle) {
        break;
      }
      $req = null;
    }
    if($req === null) {
      return new Error(ERR_NO_MATCHING_REQUEST, "No matching request found");
    }
    foreach ($registrations as $reg) {
      if($reg->keyHandle === $response->keyHandle) {
        break;
      }
      $reg = null;
    }
    if($reg === null) {
      return new Error(ERR_NO_MATCHING_REGISTRATION, "No matching registration found");
    }

    $key = U2F::pubkey_decode(bin2hex(U2F::base64u_decode($reg->publicKey)));
    if($key == null) {
      return new Error(ERR_PUBKEY_DECODE, "Decoding of public key failed");
    }
    $signData = U2F::base64u_decode($response->signatureData);
    $clientData = U2f::base64u_decode($response->clientData);
    $sha256 = hash_init('sha256');
    hash_update($sha256, hash('sha256', $req->appId, true));
    hash_update($sha256, substr($signData, 0, 5));
    hash_update($sha256, hash('sha256', $clientData, true));
    $hash = hash_final($sha256);
    $sig = U2f::sig_decode(substr($signData, 5));
    if($key->verifies(gmp_strval(gmp_init($hash, 16), 10), $sig) === true) {
      $ctr = unpack("Nctr", substr($signData, 1, 4));
      $counter = $ctr['ctr'];
      if($counter > $reg->counter) {
        $reg->counter = $counter;
        return $reg;
      } else {
        return new Error(ERR_COUNTER_TO_LOW, "Counter to low.");
      }
    } else {
      return new Error(ERR_AUTHENTICATION_FAILURE, "Authentication failed");
    }
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
      return null;
    }
    $curve = EccFactory::getNistCurves()->generator256();
    $x = gmp_strval(gmp_init(substr($key, 2, 64), 16), 10);
    $y = gmp_strval(gmp_init(substr($key, 2+64, 64), 16), 10);
    $adapter = EccFactory::getAdapter();
    return new PublicKey($curve, new Point($curve->getCurve(), $x, $y, null, $adapter), $adapter);
  }
}

/** Class for building a registration request */
class RegisterRequest {
  /** Protocol version */
  public $version = U2F_VERSION;
  /** Registration challenge */
  public $challenge;
  /** Application id */
  public $appId;

  /** @internal */
  public function __construct($challenge, $appId) {
    $this->challenge = $challenge;
    $this->appId = $appId;
  }
}

/** Class for building up an authentication request */
class SignRequest {
  /** Protocol version */
  public $version = U2F_VERSION;
  /** Authenticateion challenge */
  public $challenge;
  /** Key handle of a registered authenticator */
  public $keyHandle;
  /** Application id */
  public $appId;
}

/** Class returned for successful registrations */
class Registration {
  /** The key handle of the registered authenticator */
  public $keyHandle;
  /** The public key of the registered authenticator */
  public $publicKey;
  /** The attestation certificate of the registered authenticator */
  public $certificate;
  /** The counter associated with this registration */
  public $counter = 0;
}

/** Error class, returned on errors */
class Error {
  /** code for the error */
  public $errorCode;
  /** readable error message */
  public $errorMessage;

  /** @internal */
  public function __construct($code, $message) {
    $this->errorCode = $code;
    $this->errorMessage = $message;
  }
}

?>
