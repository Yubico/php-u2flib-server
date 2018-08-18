<?php

namespace u2flib_server;

use ParagonIE\ConstantTime\Encoding;

/**
 * Class Convert
 *
 * @package u2flib_server
 */
class Convert
{
    /**
     * @param string $data
     *
     * @return string
     */
    public static function base64uEncode($data)
    {
        return trim(strtr(Encoding::base64Encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public static function base64uDecode($data)
    {
        return Encoding::base64Decode(strtr($data, '-_', '+/'));
    }

    /**
     * Convert the public key to binary DER format first
     * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
     *
     * @param string $key
     *
     * @return null|string
     */
    public static function pubkeyToPem($key)
    {
        if (strlen($key) !== PUBKEY_LEN || $key[0] !== "\x04") {
            return null;
        }

        /*
         * Convert the public key to binary DER format first
         * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
         *
         *  SEQUENCE(2 elem)                        30 59
         *   SEQUENCE(2 elem)                       30 13
         *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
         *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
         *   BIT STRING(520 bit)                    03 42 ..key..
         */
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\0" . $key;

        $pem = "-----BEGIN PUBLIC KEY-----\r\n";
        $pem .= chunk_split(Encoding::base64Encode($der), 64);
        $pem .= '-----END PUBLIC KEY-----';

        return $pem;
    }
}
