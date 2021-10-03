<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito\Auth;

use Auth;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Exception;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Trusfin\Cognito\AwsCognitoClient;
use Trusfin\Cognito\Exceptions\NoLocalUserException;

trait AuthenticatesUsers
{
    /**
     * Attempt to log the user into the application.
     *
     * @param \string $guard          (optional)
     * @param \string $paramUsername  (optional)
     * @param \string $paramPassword  (optional)
     * @param \bool   $isJsonResponse (optional)
     *
     * @return mixed
     */
    protected function attemptLogin(Collection $request, string $guard = 'web', string $paramUsername = 'email', string $paramPassword = 'password', bool $isJsonResponse = false)
    {
        try {
            //Get key fields
            $keyUsername = 'email';
            $keyPassword = 'password';
            $rememberMe = $request->has('remember') ? $request['remember'] : false;

            //Generate credentials array
            $credentials = [
                $keyUsername => $request[$paramUsername],
                $keyPassword => $request[$paramPassword],
            ];

            //Authenticate User
            $claim = Auth::guard($guard)->attempt($credentials, $rememberMe);
        } catch (NoLocalUserException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:NoLocalUserException');

            if (config('cognito.add_missing_local_user_sso')) {
                $response = $this->createLocalUser($credentials);

                if ($response) {
                    return $response;
                }
            } //End if

            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse);
        } catch (CognitoIdentityProviderException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:CognitoIdentityProviderException');

            return $this->sendFailedCognitoResponse($e);
        } catch (Exception $e) {
            Log::error('AuthenticatesUsers:attemptLogin:Exception');

            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse);
        } //Try-catch ends

        return $claim;
    }

    /**
     * @param $token
     *
     * @throws BindingResolutionException
     */
    protected function attempLogout(Collection $request, $token, string $guard = 'api')
    {
        //Create AWS Cognito Client
        $client = app()->make(AwsCognitoClient::class);

        //Get User Data
        $user = $client->getUserByAccessToken($token);
        if (!empty($user)) {
            return Auth::guard($guard)->attempLogout($request['forever']);
        }
    }

    protected function getCognitoUserInfo($token)
    {
        $client = app()->make(AwsCognitoClient::class);

        //Get User Data
        $user = $client->getUserByAccessToken($token);
//        dd($user['UserAttributes']);
        if (!empty($user)) {
            return $user['UserAttributes'];
        }
    }

    /**
     * Create a local user if one does not exist.
     *
     * @param array $credentials
     *
     * @return mixed
     */
    protected function createLocalUser($credentials)
    {
        $userModel = config('cognito.sso_user_model');

        return $userModel::create($credentials);
    }

    //Function ends

    /**
     * Handle Failed Cognito Exception.
     */
    private function sendFailedCognitoResponse(CognitoIdentityProviderException $exception)
    {
        throw ValidationException::withMessages([
            $this->username() => $exception->getAwsErrorMessage(),
        ]);
    }

    //Function ends

    /**
     * Handle Generic Exception.
     *
     * @param \Collection $request
     * @param \Exception  $exception
     */
    private function sendFailedLoginResponse(Collection $request, Exception $exception = null, bool $isJsonResponse = false)
    {
        $message = 'FailedLoginResponse';
        if (!empty($exception)) {
            $message = $exception->getMessage();
        } //End if

        if ($isJsonResponse) {
            return response()->json([
                'error' => 'cognito.validation.auth.failed',
                'message' => $message,
            ], 400);
        }

        return redirect()
            ->withErrors([
                'username' => $message,
            ])
        ;
        //End if

        throw new HttpException(400, $message);
    }

    //Function ends
} //Trait ends
