<?php

namespace u2flib_server;

/**
 * Error class, returned on errors
 */
class Error extends \Exception
{
    /**
     * Override constructor and make message and code mandatory.
     * @param string $message
     * @param int $code
     * @param \Exception|null $previous
     */
    public function __construct($message, $code, \Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
