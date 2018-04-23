<?php

namespace u2flib_server;

/**
 * Class for building up an authentication request.
 *
 * @package u2flib_server
 */
class SignRequest
{
    /** Protocol version. */
    public $version = U2F_VERSION;

    /** Authentication challenge. */
    public $challenge;

    /** Key handle of a registered authenticator */
    public $keyHandle;

    /** Application id */
    public $appId;
}
