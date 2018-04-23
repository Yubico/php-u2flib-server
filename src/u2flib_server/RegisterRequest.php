<?php

namespace u2flib_server;

/**
 * Class for building a registration request.
 *
 * @package u2flib_server
 */
class RegisterRequest
{
    /** Protocol version */
    public $version = U2F_VERSION;

    /** Registration challenge */
    public $challenge;

    /** Application id */
    public $appId;

    /**
     * @param string $challenge
     * @param string $appId
     */
    public function __construct($challenge, $appId)
    {
        $this->challenge = $challenge;
        $this->appId = $appId;
    }
}
