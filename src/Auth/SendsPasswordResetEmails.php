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
use Illuminate\Support\Facades\Password;
use Trusfin\Cognito\AwsCognitoClient;

trait SendsPasswordResetEmails
{
    /**
     * Send a reset link to the given user.
     *
     * @param \string $usernameKey (optional)
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function sendResetLinkEmail(Collection $request, string $usernameKey = 'email', bool $resetTypeCode = true, bool $isJsonResponse = false, array $attributes = null)
    {
        //Cognito reset link
        $response = $this->sendCognitoResetLinkEmail($request[$usernameKey], $attributes);

        //JSON Response
        if ($isJsonResponse) {
            return $response;
        } //End if

        //Action Response
        if ($response) {
            if ($resetTypeCode) {
                return redirect(route('cognito.form.reset.password.code'))
                    ->withInput($request->only($usernameKey))
                    ->with('success', true)
                ;
            }

            return redirect(route('welcome'))
                ->with('success', true)
            ;
            //End if
        }

        return redirect()->back()
            ->withInput($request->only($usernameKey))
            ->withErrors([$usernameKey => 'cognito.invalid_user'])
        ;
        //End if
    }

    //Function ends

    /**
     * Send a cognito reset link to the given user.
     *
     * @param \string $username
     *
     * @return \bool
     */
    public function sendCognitoResetLinkEmail(string $username, array $attributes = null)
    {
        //Send AWS Cognito reset link
        $response = app()->make(AwsCognitoClient::class)->sendResetLink($username, $attributes);

        return Password::RESET_LINK_SENT == $response;
    }

    //Function ends
} //Trait ends
