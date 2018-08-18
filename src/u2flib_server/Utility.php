<?php

declare(strict_types=1);

namespace u2flib_server;

/**
 * Class Utility
 *
 * @package u2flib_server
 */
class Utility
{
    /**
     * @return string
     *
     * @throws \Exception
     */
    public static function createChallenge(): string
    {
        $challenge = random_bytes(32);

        return Convert::base64uEncode($challenge);
    }
}
