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

trait ResetsPasswords
{
    /**
     * Reset the given user's password.
     *
     * @param \Illuminate\Http\Request|Illuminate\Support\Collection $request
     * @param string                                                 $paramUsername (optional)
     * @param string                                                 $paramToken    (optional)
     * @param string                                                 $passwordNew   (optional)
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function reset($request, string $paramUsername = 'email', string $paramToken = 'token', string $passwordNew = 'password')
    {
        if ($request instanceof Request) {
            //Validate request
            $validator = Validator::make($request->all(), $this->resetRules());

            if ($validator->fails()) {
                throw new ValidationException($validator);
            } //End if

            $request = collect($request->all());
        } //End if

        //Create AWS Cognito Client
        $client = app()->make(AwsCognitoClient::class);

        //Get User Data
        $user = $client->getUser($request[$paramUsername]);
        if (!$user || empty($user)) {
            return 'passwords.invalid';
        }
        //Check user status and change password
        if ((AwsCognitoClient::USER_STATUS_CONFIRMED == $user['UserStatus'])
            || (AwsCognitoClient::RESET_REQUIRED_PASSWORD == $user['UserStatus'])) {
            $response = $client->resetPassword($request[$paramToken], $request[$paramUsername], $request[$passwordNew]);
        } else {
            return 'passwords.invalid';
        } //End if

        return $response;
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
    public function showResetForm(Request $request, $token = null)
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
    protected function resetRules()
    {
        return [
            'token' => 'required_without:code',
            'code' => 'required_without:token',
            'email' => 'required|email',
            'password' => 'required|confirmed|min:8',
        ];
    }

    //Function ends
} //Trait ends
