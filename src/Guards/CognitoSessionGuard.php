<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito\Guards;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result as AwsResult;
use Exception;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Request;
use Trusfin\Cognito\AwsCognitoClient;
use Trusfin\Cognito\Exceptions\AwsCognitoException;
use Trusfin\Cognito\Exceptions\InvalidUserModelException;
use Trusfin\Cognito\Exceptions\NoLocalUserException;

class CognitoSessionGuard extends SessionGuard implements StatefulGuard
{
    /**
     * @var AwsCognitoClient
     */
    protected $client;

    /**
     * @var Authentication Challenge
     */
    protected $challengeName;

    /**
     * CognitoSessionGuard constructor.
     */
    public function __construct(
        string $name,
        AwsCognitoClient $client,
        UserProvider $provider,
        Session $session,
        ?Request $request = null
    ) {
        $this->client = $client;
        parent::__construct($name, $provider, $session, $request);
    }

    /**
     * Attempt to authenticate an existing user using the credentials
     * using Cognito.
     *
     * @param bool $remember
     *
     * @throws
     *
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        try {
            //Fire event for authenticating
            $this->fireAttemptEvent($credentials, $remember);

            //Get user from presisting store
            $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

            //Check if the user exists in local data store
            if (!($user instanceof Authenticatable)) {
                throw new NoLocalUserException();
            } //End if

            //Authenticate with cognito
            if ($this->hasValidCredentials($user, $credentials)) {
                $this->login($user, $remember);

                //Fire successful attempt
                $this->fireAuthenticatedEvent($user);

                if ((!empty($this->challengeName)) && config('cognito.force_password_change_web')) {
                    switch ($this->challengeName) {
                        case AwsCognitoClient::NEW_PASSWORD_CHALLENGE:
                        case AwsCognitoClient::RESET_REQUIRED_PASSWORD:
                            return redirect(route(config('cognito.force_redirect_route_name')))
                                ->with('success', true)
                                ->with('force', true)
                                ->with('messaage', $this->challengeName)
                            ;

                            break;

                        default:
                            return true;

                            break;
                    } //End switch
                } //End if

                return true;
            } //End if

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            return false;
        } catch (NoLocalUserException $e) {
            Log::error('CognitoSessionGuard:attempt:NoLocalUserException:'.$e->getMessage());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            throw $e;
        } catch (CognitoIdentityProviderException $e) {
            Log::error('CognitoSessionGuard:attempt:CognitoIdentityProviderException:'.$e->getAwsErrorCode());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            //Set proper route
            if (!empty($e->getAwsErrorCode())) {
                switch ($e->getAwsErrorCode()) {
                    case 'PasswordResetRequiredException':
                        return redirect(route('cognito.form.reset.password.code'))
                            ->with('success', false)
                            ->with('force', true)
                            ->with('messaage', $e->getAwsErrorCode())
                        ;

                        break;

                    default:
                        return $e->getAwsErrorCode();

                        break;
                } //End switch
            } //End if

            return $e->getAwsErrorCode();
        } catch (AwsCognitoException $e) {
            Log::error('CognitoSessionGuard:attempt:AwsCognitoException:'.$e->getMessage());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            throw $e;
        } catch (Exception $e) {
            Log::error('CognitoSessionGuard:attempt:Exception:'.$e->getMessage());

            //Fire failed attempt
            $this->fireFailedEvent($user, $credentials);

            return false;
        } //Try-catch ends
    }

    //Function ends

    /**
     * @param mixed $user
     * @param array $credentials
     *
     * @throws InvalidUserModelException
     *
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        // @var Result $result
        try {
            $result = $this->client->authenticate($credentials['email'], $credentials['password']);
        } catch (Exception $e) {
            return false;
        }

        if ($result instanceof AwsResult) {
            if (
                isset($result['ChallengeName'])
                && in_array($result['ChallengeName'], config('cognito.forced_challenge_names'))
            ) {
                $this->challengeName = $result['ChallengeName'];
            }

            $this->parseAuthenticationResult($result);

            return 200 === $result['@metadata']['statusCode'] && isset($result['AuthenticationResult']['AccessToken']);
        }

        return false;
    }

    /**
     * @param array|AwsResult $result
     */
    protected function parseAuthenticationResult($result)
    {
        if (isset($result['AuthenticationResult']['AccessToken'])) {
            $this->getSession()->put(config('cognito.session_access_token_key'), $result['AuthenticationResult']['AccessToken']);
            $this->getSession()->put(config('cognito.session_refresh_token_key'), $result['AuthenticationResult']['RefreshToken']);
            $this->getSession()->put(config('cognito.session_id_token_key'), $result['AuthenticationResult']['IdToken']);
        }
    }
} //Class ends
