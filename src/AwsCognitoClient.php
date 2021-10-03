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

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Password;
use PHPUnit\Exception;

class AwsCognitoClient
{
    /**
     * Constant representing the user status as Confirmed.
     *
     * @var string
     */
    public const USER_STATUS_CONFIRMED = 'CONFIRMED';

    /**
     * Constant representing the user needs a new password.
     *
     * @var string
     */
    public const NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED';

    /**
     * Constant representing the user needs to reset password.
     *
     * @var string
     */
    public const RESET_REQUIRED_PASSWORD = 'RESET_REQUIRED';

    /**
     * Constant representing the force new password status.
     *
     * @var string
     */
    public const FORCE_CHANGE_PASSWORD = 'FORCE_CHANGE_PASSWORD';

    /**
     * Constant representing the password reset required exception.
     *
     * @var string
     */
    public const RESET_REQUIRED = 'PasswordResetRequiredException';

    /**
     * Constant representing the user not found exception.
     *
     * @var string
     */
    public const USER_NOT_FOUND = 'UserNotFoundException';

    /**
     * Constant representing the username exists exception.
     *
     * @var string
     */
    public const USERNAME_EXISTS = 'UsernameExistsException';

    /**
     * Constant representing the invalid password exception.
     *
     * @var string
     */
    public const INVALID_PASSWORD = 'InvalidPasswordException';

    /**
     * Constant representing the code mismatch exception.
     *
     * @var string
     */
    public const CODE_MISMATCH = 'CodeMismatchException';

    /**
     * Constant representing the expired code exception.
     *
     * @var string
     */
    public const EXPIRED_CODE = 'ExpiredCodeException';

    /**
     * Constant representing the SMS MFA challenge.
     *
     * @var string
     */
    public const SMS_MFA = 'SMS_MFA';

    /**
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $poolId;

    /**
     * AwsCognitoClient constructor.
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $poolId
     */
    public function __construct(
        CognitoIdentityProviderClient $client,
        $clientId,
        $clientSecret,
        $poolId
    ) {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }

    /**
     * Checks if credentials of a user are valid.
     *
     * @see http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @param string $username
     * @param string $password
     *
     * @return \Aws\Result|bool
     */
    public function authenticate($username, $password)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $exception) {
            throw $exception;
        }

        return $response;
    }

    //Function ends

    /**
     * @param $username
     * @param $password
     *
     * @return \Aws\Result|false
     */
    public function register($username, $password, array $attributes = [])
    {
        try {
            $response = $this->client->signUp([
                'ClientId' => $this->clientId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'UserAttributes' => $this->formatAttributes($attributes),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USERNAME_EXISTS === $e->getAwsErrorCode()) {
                return false;
            } //End if

            throw $e;
        }

        //        return (bool)$response['UserConfirmed'];
        return $response;
    }

    //Function ends

    /**
     * Send a password reset code to a user.
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
     *
     * @param string $username
     * @param array  $clientMetadata (optional)
     *
     * @return string
     */
    public function sendResetLink($username, array $clientMetadata = null)
    {
        try {
            //Build payload
            $payload = [
                'ClientId' => $this->clientId,
                'ClientMetadata' => $this->buildClientMetadata(['username' => $username], $clientMetadata),
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ];

            $result = $this->client->forgotPassword($payload);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return Password::INVALID_USER;
            } //End if

            throw $e;
        }

        return Password::RESET_LINK_SENT;
    }

    //Function ends

    /**
     * Reset a users password based on reset code.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html.
     *
     * @param string $code
     * @param string $username
     * @param string $password
     *
     * @return string
     */
    public function resetPassword($code, $username, $password)
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId' => $this->clientId,
                'ConfirmationCode' => $code,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return Password::INVALID_USER;
            }

            if (self::INVALID_PASSWORD === $e->getAwsErrorCode()) {
                return Lang::has('passwords.password') ? 'passwords.password' : $e->getAwsErrorMessage();
            }

            if (self::CODE_MISMATCH === $e->getAwsErrorCode() || self::EXPIRED_CODE === $e->getAwsErrorCode()) {
                return Password::INVALID_TOKEN;
            }

            if ('LimitExceededException' === $e->getAwsErrorCode()) {
                return 'Attempt limit exceeded, please try after some time';
            }

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }

    //Function ends

    /**
     * Register a user and send them an email to set their password.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html.
     *
     * @param $username
     * @param array $clientMetadata (optional)
     *
     * @return bool
     */
    public function inviteUser(string $username, string $password = null, array $attributes = [], array $clientMetadata = null)
    {
        //Force validate email
        if ($attributes['email']) {
            $attributes['email_verified'] = 'true';
        } //End if

        //Generate payload
        $payload = [
            'UserPoolId' => $this->poolId,
            'Username' => $username,
            'UserAttributes' => $this->formatAttributes($attributes),
        ];

        //Set Client Metadata
        if (!empty($clientMetadata)) {
            $payload['ClientMetadata'] = $this->buildClientMetadata([], $clientMetadata);
        } //End if

        //Set Temporary password
        if (!empty($password)) {
            $payload['TemporaryPassword'] = $password;
        } //End if

        if ('DEFAULT' != config('cognito.add_user_delivery_mediums')) {
            $payload['DesiredDeliveryMediums'] = [
                config('cognito.add_user_delivery_mediums'),
            ];
        } //End if

        try {
            $this->client->adminCreateUser($payload);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USERNAME_EXISTS === $e->getAwsErrorCode()) {
                return false;
            } //End if

            throw $e;
        }

        return true;
    }

    //Function ends

    /**
     * Set a new password for a user that has been flagged as needing a password change.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html.
     *
     * @param string $username
     * @param string $password
     * @param string $session
     *
     * @return bool
     */
    public function confirmPassword($username, $password, $session)
    {
        try {
            $this->client->AdminRespondToAuthChallenge([
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
                'Session' => $session,
                'ChallengeResponses' => [
                    'NEW_PASSWORD' => $password,
                    'USERNAME' => $username,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::CODE_MISMATCH === $e->getAwsErrorCode() || self::EXPIRED_CODE === $e->getAwsErrorCode()) {
                return Password::INVALID_TOKEN;
            } //End if

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }

    //Function ends

    /**
     * @param string $username
     *
     * @see https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#admindeleteuser
     */
    public function deleteUser($username)
    {
        if (config('cognito.delete_user')) {
            $this->client->adminDeleteUser([
                'UserPoolId' => $this->poolId,
                'Username' => $username,
            ]);
        } //End if
    }

    //Function ends

    /**
     * Sets the specified user's password in a user pool as an administrator.
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html
     *
     * @param string $username
     * @param string $password
     * @param bool   $permanent
     *
     * @return bool
     */
    public function setUserPassword($username, $password, $permanent = true)
    {
        try {
            $this->client->adminSetUserPassword([
                'Password' => $password,
                'Permanent' => $permanent,
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return Password::INVALID_USER;
            } //End if

            if (self::INVALID_PASSWORD === $e->getAwsErrorCode()) {
                return Lang::has('passwords.password') ? 'passwords.password' : $e->getAwsErrorMessage();
            } //End if

            throw $e;
        }

        return Password::PASSWORD_RESET;
    }

    //Function ends

    /**
     * Changes the password for a specified user in a user pool.
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChangePassword.html
     *
     * @return bool
     */
    public function changePassword(string $accessToken, string $passwordOld, string $passwordNew)
    {
        try {
            $this->client->changePassword([
                'AccessToken' => $accessToken,
                'PreviousPassword' => $passwordOld,
                'ProposedPassword' => $passwordNew,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return Password::INVALID_USER;
            } //End if

            if (self::INVALID_PASSWORD === $e->getAwsErrorCode()) {
                return Lang::has('passwords.password') ? 'passwords.password' : $e->getAwsErrorMessage();
            }

            if ('NotAuthorizedException' === $e->getAwsErrorCode() || 'LimitExceededException' === $e->getAwsErrorCode()) {
                return false;
            } //End if

            throw $e;
        }

        return true;
    }

    public function invalidatePassword($username)
    {
        $this->client->adminResetUserPassword([
            'UserPoolId' => $this->poolId,
            'Username' => $username,
        ]);
    }

    public function confirmSignUp($username)
    {
        $this->client->adminConfirmSignUp([
            'UserPoolId' => $this->poolId,
            'Username' => $username,
        ]);
    }

    //Function ends

    public function confirmUserSignUp($username, $confirmationCode)
    {
        try {
            $userInfo = $this->getUser($username);
//            dd($userInfo);
            return $this->client->confirmSignUp([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
                'ConfirmationCode' => $confirmationCode,
            ]);

            // now get user to send email verification code
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return 'validation.invalid_user';
            } //End if

            if (self::CODE_MISMATCH === $e->getAwsErrorCode() || self::EXPIRED_CODE === $e->getAwsErrorCode()) {
                return 'validation.invalid_token';
            } //End if

            if ('NotAuthorizedException' === $e->getAwsErrorCode() and 'User cannot be confirmed. Current status is CONFIRMED' === $e->getAwsErrorMessage()) {
                return 'validation.confirmed';
            } //End if

            if ('LimitExceededException' === $e->getAwsErrorCode()) {
                return 'validation.exceeded';
            } //End if

            throw $e;
        }
    }

    //Function ends

    public function resendToken($username)
    {
        try {
            $this->client->resendConfirmationCode([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return 'validation.invalid_user';
            } //End if

            if ('LimitExceededException' === $e->getAwsErrorCode()) {
                return 'validation.exceeded';
            } //End if

            if ('InvalidParameterException' === $e->getAwsErrorCode()) {
                return 'validation.confirmed';
            } //End if

            throw $e;
        }
    }

    //Function ends

    // HELPER FUNCTIONS

    /**
     * Set a users attributes.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html.
     *
     * @return bool
     */
    public function setUserAttributes(string $username, array $attributes)
    {
        try {
            $this->client->AdminUpdateUserAttributes([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
                'UserAttributes' => $this->formatAttributes($attributes),
            ]);
        } catch (CognitoIdentityProviderException $e) {
            if (self::USER_NOT_FOUND === $e->getAwsErrorCode()) {
                return 'validation.invalid_user';
            }

            if ('NotAuthorizedException' === $e->getAwsErrorCode()) {
                return 'validation.user_not_authorized';
            }

            if ('InvalidParameterException' === $e->getAwsErrorCode()) {
                return 'validation.invalid_parameter';
            }

            throw $e;
        }

        return 'user.updated';
    }

    //Function ends

    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html.
     *
     * @param string $username
     *
     * @return mixed
     */
    public function getUser($username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return $user;
    }

    //Function ends

    /**
     * Responds to MFA challenge.
     * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html.
     *
     * @return \Aws\Result|false
     */
    public function respondMFAChallenge(string $session, string $challengeValue, string $username, string $challengeName = AwsCognitoClient::SMS_MFA)
    {
        try {
            $challenge = $this->client->AdminRespondToAuthChallenge([
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
                'ChallengeName' => $challengeName,
                'ChallengeResponses' => [
                    'SMS_MFA_CODE' => $challengeValue,
                    'USERNAME' => $username,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'Session' => $session,
            ]);
//            dd($challenge);
        } catch (CognitoIdentityProviderException $e) {
//            dd($e);
            if ('NotAuthorizedException' === $e->getAwsErrorCode()) {
                return 'mfa.not_authorized';
            }
            if (self::CODE_MISMATCH === $e->getAwsErrorCode()) {
                return 'mfa.invalid_session';
            }

            return false;
        }

        return $challenge;
    }

    /**
     * Get user details by access token.
     * https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#getuser.
     *
     * @return mixed
     */
    public function getUserByAccessToken(string $token)
    {
        try {
            $result = $this->client->getUser([
                'AccessToken' => $token,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw $e;
        } //Try-catch ends

        return $result;
    }

    //Function ends

    /**
     * Creates the Cognito secret hash.
     *
     * @param string $username
     *
     * @return string
     */
    protected function cognitoSecretHash($username)
    {
        return $this->hash($username.$this->clientId);
    }

    //Function ends

    /**
     * Creates a HMAC from a string.
     *
     * @param string $message
     *
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }

    //Function ends

    /**
     * Format attributes in Name/Value array.
     *
     * @return array
     */
    protected function formatAttributes(array $attributes)
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        } //Loop ends

        return $userAttributes;
    }

    //Function ends

    /**
     * Build Client Metadata to be forwarded to Cognito.
     *
     * @return array $clientMetadata (optional)
     */
    protected function buildClientMetadata(array $attributes, array $clientMetadata = null)
    {
        if (!empty($clientMetadata)) {
            $userAttributes = array_merge($attributes, $clientMetadata);
        } else {
            $userAttributes = $attributes;
        } //End if

        return $userAttributes;
    }

    //Function ends
} //Class ends
