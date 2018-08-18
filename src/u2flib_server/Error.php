<?php

declare(strict_types=1);

namespace u2flib_server;

use Exception;

/**
 * Error class, returned on errors
 *
 * @package u2flib_server
 */
class Error extends Exception
{
    /**
     * Override constructor and make message and code mandatory
     *
     * @param string          $message
     * @param int             $code
     * @param Exception|null $previous
     */
    public function __construct(string $message, int $code, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
