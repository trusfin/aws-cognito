<?php

namespace Trusfin\Cognito\Exceptions;

use Exception;
use Illuminate\Auth\AuthenticationException;
use Throwable;

class NoTokenException extends Exception
{
    /**
     * Report the exception.
     *
     * @param mixed $message
     */
    public function report($message = 'Authentication token not provided')
    {
        throw new AuthenticationException($message);
    }

    /**
     * Render the exception into an HTTP response.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\Response
     */
    public function render($request, Throwable $exception)
    {
        return parent::render($request, $exception);
    }
} //Class ends
