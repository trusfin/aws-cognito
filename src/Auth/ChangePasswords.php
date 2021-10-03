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

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Trusfin\Cognito\AwsCognitoClient;

trait ChangePasswords
{
    /**
     * Change the given user's password.
     *
     * @param \Illuminate\Http\Request|Illuminate\Support\Collection $request
     * @param string                                                 $paramUsername (optional)
     * @param string                                                 $passwordOld   (optional)
     * @param string                                                 $passwordNew   (optional)
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function changeUsersPassword($request, string $token, $paramUsername = 'email', string $passwordOld = 'password', string $passwordNew = 'new_password')
    {
        if ($request instanceof Request) {
            //Validate request
            $validator = Validator::make($request->all(), $this->passRules());

            if ($validator->fails()) {
                throw new ValidationException($validator);
            } //End if

            $request = collect($request->all());
        } //End if

        //Create AWS Cognito Client
        $client = app()->make(AwsCognitoClient::class);
//        dd($request->bearerToken());
        //Get User Data
        $user = $client->getUser($request[$paramUsername]);
//        dd($user);
        if (empty($user)) {
            $response = response()->json(['status' => 'error', 'message' => 'invalid email'], 400);
        } else {
//            if (AwsCognitoClient::FORCE_CHANGE_PASSWORD == $user['UserStatus']) {
//                $response = $this->forceNewPassword($client, $request, $paramUsername, $passwordOld, $passwordNew);
//            } elseif (AwsCognitoClient::RESET_REQUIRED_PASSWORD == $user['UserStatus']) {
//                $response = response()->json(['error' => 'cognito.validation.reset_required.invalid_request'], 400);
//            } else {
            $response = $this->changePassword($client, $request, $token, $paramUsername, $passwordOld, $passwordNew);
//            } //End if
        } //End if

        return $response;
        // return $response == Password::PASSWORD_RESET
        //     ? $this->sendResetResponse($request, $response)
        //     : $this->sendResetFailedResponse($request, $response);
    }

    //Function ends

    /**
     * Display the password reset view for the given token.
     *
     * If no token is present, display the link request form.
     *
     * @param null|string $token
     *
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     */
    public function showChangePasswordForm(Request $request, $token = null)
    {
        return view('vendor.black-bits.laravel-cognito-auth.reset-password')->with(
            ['email' => $request->email]
        );
    }

    //Function ends

    /**
     * Get the password reset validation rules.
     *
     * @return array
     */
    protected function passRules()
    {
        return [
            'email' => 'required|email',
            'password' => 'string|min:8',
            'new_password' => 'required|confirmed|min:8',
        ];
    }

    //Function ends

    /**
     * If a user is being forced to set a new password for the first time follow that flow instead.
     *
     * @param \Illuminate\Support\Collection $request
     *
     * @return string
     */
    private function forceNewPassword(AwsCognitoClient $client, $request, string $paramUsername, string $passwordOld, string $passwordNew)
    {
        //Authenticate user
        $login = $client->authenticate($request[$paramUsername], $request[$passwordOld]);

        return $client->confirmPassword($request[$paramUsername], $request[$passwordNew], $login->get('Session'));
    }

    //Function ends

    /**
     * If a user is being forced to set a new password for the first time follow that flow instead.
     *
     * @param \Illuminate\Support\Collection $request
     * @param mixed                          $token
     *
     * @return string
     */
    private function changePassword(AwsCognitoClient $client, $request, $token, string $paramUsername, string $passwordOld, string $passwordNew)
    {
        return $client->changePassword($token, $request[$passwordOld], $request[$passwordNew]);
    }

    //Function ends
} //Trait ends
