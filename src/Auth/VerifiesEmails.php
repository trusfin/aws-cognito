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

use Illuminate\Support\Collection;
use Trusfin\Cognito\AwsCognitoClient;

trait VerifiesEmails
{
    /**
     * Mark the authenticated user's email address as verified.
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function verify(Collection $request)
    {
//        $validator = Validator::make($request, [
//            'email' => 'required|email',
//            'confirmation_code' => 'required|numeric',
//        ]);

        return app()->make(AwsCognitoClient::class)->confirmUserSignUp($request['email'], $request['confirmation_code']);
        if ('validation.invalid_user' == $response) {
            return redirect()->back()
                ->withInput($request->only('email'))
                ->withErrors(['email' => 'cognito.validation.invalid_user'])
            ;
        }

        if ('validation.invalid_token' == $response) {
            return redirect()->back()
                ->withInput($request->only('email'))
                ->withErrors(['confirmation_code' => 'cognito.validation.invalid_token'])
            ;
        }

        if ('validation.exceeded' == $response) {
            return redirect()->back()
                ->withInput($request->only('email'))
                ->withErrors(['confirmation_code' => 'cognito.validation.exceeded'])
            ;
        }

        if ('validation.confirmed' == $response) {
            return redirect($this->redirectPath())->with('verified', true);
        }

        return redirect($this->redirectPath())->with('verified', true);
    }

    //Function ends

    /**
     * Resend the email verification notification.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function resend(Collection $request)
    {
        $response = app()->make(AwsCognitoClient::class)->resendToken($request['email']);

        if ('validation.invalid_user' == $response) {
            return response()->json(['error' => 'cognito.validation.invalid_user'], 400);
        }

        if ('validation.exceeded' == $response) {
            return response()->json(['error' => 'cognito.validation.exceeded'], 400);
        }

        if ('validation.confirmed' == $response) {
            return response()->json(['error' => 'cognito.validation.confirmed'], 400);
        }

        return response()->json(['success' => 'true']);
    }

    //Function ends
} //Trait ends
