<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito\Http\Middleware;

use Exception;
use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Trusfin\Cognito\AwsCognito;
use Trusfin\Cognito\Exceptions\NoTokenException;

abstract class BaseMiddleware //extends Middleware
{
    /**
     * The Cognito Authenticator.
     *
     * @var \Trusfin\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * Create a new BaseMiddleware instance.
     */
    public function __construct(AwsCognito $cognito)
    {
        $this->cognito = $cognito;
    }

    /**
     * Check the request for the presence of a token.
     *
     * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     */
    public function checkForToken(Request $request)
    {
        if (!$this->cognito->parser()->setRequest($request)->hasToken()) {
            throw new NoTokenException();
        } //End if
    }

    //Function ends

    /**
     * Attempt to authenticate a user via the token in the request.
     *
     * @throws \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     */
    public function authenticate(Request $request)
    {
        try {
            $this->checkForToken($request);

            if (!$this->cognito->parseToken()->authenticate()) {
                throw new UnauthorizedHttpException('aws-cognito', 'User not found');
            } //End if
        } catch (Exception $e) {
            throw $e;
        } //Try-catch ends
    }

    //Function ends

    /**
     * Set the authentication header.
     *
     * @param \Illuminate\Http\JsonResponse|\Illuminate\Http\Response $response
     * @param null|string                                             $token
     *
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\Response
     */
    protected function setAuthenticationHeader($response, $token = null)
    {
        $token = $token ?: $this->cognito->refresh();
        $response->headers->set('Authorization', 'Bearer '.$token);

        return $response;
    }

    //Function ends
} //Class ends
