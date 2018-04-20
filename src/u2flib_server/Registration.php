<?php

namespace u2flib_server;

/**
 * Class returned for successful registrations
 *
 * @package u2flib_server
 */
class Registration
{
    /** The key handle of the registered authenticator */
    public $keyHandle;

    /** The public key of the registered authenticator */
    public $publicKey;

    /** The attestation certificate of the registered authenticator */
    public $certificate;

    /** The counter associated with this registration */
    public $counter = -1;
}