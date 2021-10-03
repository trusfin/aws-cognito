<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito;

use Trusfin\Cognito\Exceptions\AwsCognitoException;
use Trusfin\Cognito\Exceptions\InvalidTokenException;
use Trusfin\Cognito\Http\Parser\Parser;

class AwsCognito
{
    /**
     * The authentication provider.
     *
     * @var \Trusfin\Cognito\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Aws Cognito Manager.
     *
     * @var \Trusfin\Cognito\AwsCognitoManager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \Trusfin\Cognito\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The AwsCognito Claim token.
     *
     * @var null|\Trusfin\Cognito\AwsCognitoClaim
     */
    protected $claim;

    /**
     * The AWS Cognito token.
     *
     * @var null|string|\Trusfin\Cognito\AwsCognitoToken
     */
    protected $token;

    /**
     * JWT constructor.
     *
     * @param \Trusfin\Cognito\Manager $manager
     */
    public function __construct(AwsCognitoManager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Get the token.
     *
     * @return null|\Trusfin\Cognito\AwsCognitoToken
     */
    public function getToken()
    {
        if (null === $this->token) {
            try {
                $this->parseToken();
            } catch (AwsCognitoException $e) {
                $this->token = null;
            }
        } //End if

        return $this->token;
    }

    //Function ends

    /**
     * Parse the token from the request.
     *
     * @throws \Trusfin\Cognito\Exceptions\AwsCognitoException
     *
     * @return \Trusfin\Cognito\AwsCognito
     */
    public function parseToken()
    {
        //Parse the token
        $token = $this->parser->parseToken();

        if (empty($token)) {
            throw new AwsCognitoException('The token could not be parsed from the request');
        } //End if

        return $this->setToken($token);
    }

    //Function ends

    /**
     * Set the token.
     *
     * @param \string $token
     *
     * @return \Trusfin\Cognito\AwsCognito
     */
    public function setToken(string $token)
    {
        $this->token = (new AwsCognitoToken($token));
        if (empty($this->token)) {
            throw new AwsCognitoException('The token could not be validated.');
        } //End if

        return $this;
    }

    //Function ends

    /**
     * Get the token.
     *
     * @return null|\Trusfin\Cognito\AwsCognitoClaim
     */
    public function getClaim()
    {
        return (!empty($this->claim)) ? $this->claim : null;
    }

    //Function ends

    /**
     * Set the claim.
     *
     * @return \Trusfin\Cognito\AwsCognito
     */
    public function setClaim(AwsCognitoClaim $claim)
    {
        $this->claim = $claim;
        $this->token = $this->setToken($claim->getToken());

        return $this;
    }

    //Function ends

    /**
     * Unset the current token.
     *
     * @param mixed $forceForever
     *
     * @return \Trusfin\Cognito\AwsCognito
     */
    public function unsetToken($forceForever = false)
    {
        $tokenKey = $this->token->get();
        $this->manager->release($tokenKey);
        $this->claim = null;
        $this->token = null;

        return $this;
    }

    /**
     * Set the request instance.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Trusfin\Cognito\AwsCognito
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    //Function ends

    /**
     * Get the Parser instance.
     *
     * @return \Trusfin\Cognito\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    }

    //Function ends

    /**
     * Authenticate a user via a token.
     *
     * @return false|\Trusfin\Cognito\AwsCognito
     */
    public function authenticate()
    {
        $claim = $this->manager->fetch($this->token->get())->decode();
        $this->claim = $claim;

        if (empty($this->claim)) {
            throw new InvalidTokenException();
        } //End if

        return $this; //->user();
    }

    //Function ends

    /**
     * Alias for authenticate().
     *
     * @return false|\Tymon\JWTAuth\Contracts\JWTSubject
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    //Function ends

    /**
     * Get the authenticated user.
     *
     * @throws InvalidTokenException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function user()
    {
        //Get Claim
        if (empty($this->claim)) {
            throw new InvalidTokenException();
        } //End if

        return $this->claim->getUser();
    }

    //Function ends

    /**
     * Persist token.
     *
     * @return \boolean
     */
    public function storeToken()
    {
        return $this->manager->encode($this->claim)->store();
    }

    //Function ends
} //Class ends
