<?php

declare(strict_types=1);

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

use InvalidArgumentException;
use ParagonIE\ConstantTime\Encoding;

/** Constant for the version of the u2f protocol */
const U2F_VERSION = 'U2F_V2';

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
const ERR_COUNTER_TOO_LOW = 8;

/** Error decoding public key */
const ERR_PUBKEY_DECODE = 9;

/** Error user-agent returned error */
const ERR_BAD_UA_RETURNING = 10;

/** Error old OpenSSL version */
const ERR_OLD_OPENSSL = 11;

/** @internal */
const PUBKEY_LEN = 65;

/**
 * Class U2F
 *
 * @package u2flib_server
 */
class U2F
{
    /** @var string  */
    private $appId;

    /** @var null|string */
    private $attestDir;

    /** @internal */
    private $fixCerts = [
        '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
        'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
        '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
        'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
        '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
        'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511'
    ];

    const HASH_ALGORITHM = 'sha256';

    /**
     * U2F constructor.
     *
     * @param string $appId Application id for the running application
     * @param string|null $attestDir Directory where trusted attestation roots may be found
     *
     * @throws Error If OpenSSL older than 1.0.0 is used
     */
    public function __construct(string $appId, string $attestDir = null)
    {
        if (OPENSSL_VERSION_NUMBER < 0x10000000) {
            throw new Error(
                'OpenSSL has to be at least version 1.0.0, this is ' . OPENSSL_VERSION_TEXT,
                ERR_OLD_OPENSSL
            );
        }

        $this->appId = $appId;
        $this->attestDir = $attestDir;
    }

    /**
     * Called to get a registration request to send to a user.
     * Returns an array of one registration request and a array of sign requests.
     *
     * @param array $registrations List of current registrations for this
     *                             user, to prevent the user from registering the same authenticator several
     *                             times.
     *
     * @return array An array of two elements, the first containing a
     * RegisterRequest the second being an array of SignRequest
     *
     * @throws \Exception
     */
    public function getRegisterData(array $registrations = []): array
    {
        $challenge = Utility::createChallenge();
        $request = new RegisterRequest($challenge, $this->appId);
        $signs = $this->getAuthenticateData($registrations);

        return [$request, $signs];
    }

    /**
     * Called to verify and unpack a registration message.
     *
     * @param RegisterRequest $request this is a reply to
     * @param object $response response from a user
     * @param bool $includeCert set to true if the attestation certificate should be
     * included in the returned Registration object
     * @return Registration
     * @throws Error
     */
    public function doRegister($request, $response, $includeCert = true): Registration
    {
        if (!is_object($request)) {
            throw new InvalidArgumentException('$request of doRegister() method only accepts object.');
        }

        if (!is_object($response)) {
            throw new InvalidArgumentException('$response of doRegister() method only accepts object.');
        }

        if (property_exists($response, 'errorCode') && $response->errorCode !== 0) {
            throw new Error(
                'User-agent returned error. Error code: ' . $response->errorCode,
                ERR_BAD_UA_RETURNING
            );
        }

        if (!is_bool($includeCert)) {
            throw new InvalidArgumentException('$include_cert of doRegister() method only accepts boolean.');
        }

        $rawReg = Convert::base64uDecode($response->registrationData);
        $regData = array_values(unpack('C*', $rawReg));

        $clientData = Convert::base64uDecode($response->clientData);
        $cli = json_decode($clientData);

        if ($cli->challenge !== $request->challenge) {
            throw new Error('Registration challenge does not match', ERR_UNMATCHED_CHALLENGE);
        }

        $registration = new Registration();
        $offs = 1;
        $pubKey = substr($rawReg, $offs, PUBKEY_LEN);
        $offs += PUBKEY_LEN;
        // decode the pubKey to make sure it's good
        $tmpKey = Convert::pubkeyToPem($pubKey);

        if ($tmpKey === null) {
            throw new Error('Decoding of public key failed', ERR_PUBKEY_DECODE);
        }

        $registration->publicKey = Encoding::base64Encode($pubKey);
        $khLen = $regData[$offs++];
        $kh = substr($rawReg, $offs, $khLen);
        $offs += $khLen;
        $registration->keyHandle = Convert::base64uEncode($kh);

        // length of certificate is stored in byte 3 and 4 (excluding the first 4 bytes)
        $certLen = 4;
        $certLen += ($regData[$offs + 2] << 8);
        $certLen += $regData[$offs + 3];

        $rawCert = $this->fixSignatureUnusedBits(substr($rawReg, $offs, $certLen));
        $offs += $certLen;

        $pemCert  = "-----BEGIN CERTIFICATE-----\r\n";
        $pemCert .= chunk_split(Encoding::base64Encode($rawCert), 64);
        $pemCert .= '-----END CERTIFICATE-----';

        if ($includeCert) {
            $registration->certificate = Encoding::base64Encode($rawCert);
        }

        if ($this->attestDir && openssl_x509_checkpurpose($pemCert, -1, $this->getCerts()) !== true) {
            throw new Error(
                'Attestation certificate can not be validated',
                ERR_ATTESTATION_VERIFICATION
            );
        }

        if (!openssl_pkey_get_public($pemCert)) {
            throw new Error('Decoding of public key failed', ERR_PUBKEY_DECODE);
        }

        $signature = substr($rawReg, $offs);

        $dataToVerify  = chr(0);
        $dataToVerify .= hash(static::HASH_ALGORITHM, $request->appId, true);
        $dataToVerify .= hash(static::HASH_ALGORITHM, $clientData, true);
        $dataToVerify .= $kh;
        $dataToVerify .= $pubKey;

        if (openssl_verify($dataToVerify, $signature, $pemCert, static::HASH_ALGORITHM) === 1) {
            return $registration;
        }

        throw new Error('Attestation signature does not match', ERR_ATTESTATION_SIGNATURE);
    }

    /**
     * Called to get an authentication request.
     *
     * @param array $registrations An array of the registrations to create authentication requests for.
     *
     * @return array An array of SignRequest
     * @throws \Exception
     */
    public function getAuthenticateData(array $registrations): array
    {
        $sigs = [];

        $challenge = Utility::createChallenge();

        foreach ($registrations as $reg) {
            if (!is_object($reg)) {
                throw new InvalidArgumentException(
                    '$registrations of getAuthenticateData() method only accepts array of object.'
                );
            }

            $sig = new SignRequest();
            $sig->appId = $this->appId;
            $sig->keyHandle = $reg->keyHandle;
            $sig->challenge = $challenge;

            $sigs[] = $sig;
        }

        return $sigs;
    }

    /**
     * Called to verify an authentication response
     *
     * @param array $requests An array of outstanding authentication requests
     * @param array $registrations An array of current registrations
     * @param object $response A response from the authenticator
     * @return Registration
     * @throws Error
     *
     * The Registration object returned on success contains an updated counter
     * that should be saved for future authentications.
     * If the Error returned is ERR_COUNTER_TOO_LOW this is an indication of
     * token cloning or similar and appropriate action should be taken.
     */
    public function doAuthenticate(array $requests, array $registrations, $response)
    {
        if (!is_object($response)) {
            throw new InvalidArgumentException('$response of doAuthenticate() method only accepts object.');
        }

        if (property_exists($response, 'errorCode') && $response->errorCode !== 0) {
            throw new Error(
                'User-agent returned error. Error code: ' . $response->errorCode,
                ERR_BAD_UA_RETURNING
            );
        }

        /** @var object|null $request */
        $request = null;

        /** @var object|null $registration */
        $registration = null;

        $clientData = Convert::base64uDecode($response->clientData);
        $decodedClient = json_decode($clientData);

        foreach ($requests as $request) {
            if (!is_object($request)) {
                throw new InvalidArgumentException(
                    '$requests of doAuthenticate() method only accepts array of object.'
                );
            }

            if ($request->keyHandle === $response->keyHandle && $request->challenge === $decodedClient->challenge) {
                break;
            }

            $request = null;
        }

        if ($request === null) {
            throw new Error('No matching request found', ERR_NO_MATCHING_REQUEST);
        }

        foreach ($registrations as $registration) {
            if (!is_object($registration)) {
                throw new InvalidArgumentException(
                    '$registrations of doAuthenticate() method only accepts array of object.'
                );
            }

            if ($registration->keyHandle === $response->keyHandle) {
                break;
            }

            $registration = null;
        }

        if ($registration === null) {
            throw new Error('No matching registration found', ERR_NO_MATCHING_REGISTRATION);
        }

        $pemKey = Convert::pubkeyToPem(Convert::base64uDecode($registration->publicKey));

        if ($pemKey === null) {
            throw new Error('Decoding of public key failed', ERR_PUBKEY_DECODE);
        }

        $signData = Convert::base64uDecode($response->signatureData);

        $dataToVerify  = hash(static::HASH_ALGORITHM, $request->appId, true);
        $dataToVerify .= substr($signData, 0, 5);
        $dataToVerify .= hash(static::HASH_ALGORITHM, $clientData, true);

        $signature = substr($signData, 5);

        if (openssl_verify($dataToVerify, $signature, $pemKey, static::HASH_ALGORITHM) === 1) {
            $ctr = unpack('Nctr', substr($signData, 1, 4));
            $counter = $ctr['ctr'];

            /* TODO: wrap-around should be handled somehow.. */
            if ($counter > $registration->counter) {
                $registration->counter = $counter;

                return $registration;
            }

            throw new Error('Counter too low.', ERR_COUNTER_TOO_LOW);
        }

        throw new Error('Authentication failed', ERR_AUTHENTICATION_FAILURE);
    }

    /**
     * @return array
     */
    private function getCerts(): array
    {
        $files = [];
        $dir = $this->attestDir;

        if ($dir && $handle = opendir($dir)) {
            while (($entry = readdir($handle)) !== false) {
                if (is_file("$dir/$entry")) {
                    $files[] = "$dir/$entry";
                }
            }

            closedir($handle);
        }

        return $files;
    }

    /**
     * Fixes a certificate where the signature contains unused bits.
     *
     * @param string $cert
     * @return string
     */
    private function fixSignatureUnusedBits(string $cert): string
    {
        if (in_array(hash(static::HASH_ALGORITHM, $cert), $this->fixCerts, true)) {
            $cert[strlen($cert) - 257] = "\0";
        }

        return $cert;
    }
}
