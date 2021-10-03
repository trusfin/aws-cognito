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
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Trusfin\Cognito\AwsCognitoClient;
use Trusfin\Cognito\Exceptions\InvalidUserFieldException;

trait UpdateUsers
{
    /**
     * Handle a registration request for the application.
     *
     * @throws InvalidUserFieldException
     *
     * @return \Illuminate\Http\Response
     */
    public function updateCognitoUser(Collection $request, array $clientMetadata = null)
    {
        //Initialize Cognito Attribute array
        $attributes = [];

        // Get the update user fields
        $userFields = config('cognito.cognito_user_fields');

        //Iterate the fields
        foreach ($userFields as $key => $userField) {
            if ($request->has($userField)) {
                $attributes[$key] = $request->get($userField);
            } else {
                Log::error('RegistersUsers:createCognitoUser:InvalidUserFieldException');
                Log::error("The configured user field {$userField} is not provided in the request.");

                throw new InvalidUserFieldException("The configured user field {$userField} is not provided in the request.");
            } //End if
        } //Loop ends

        //Register the user in Cognito
        $userKey = $request->has('username') ? 'username' : 'email';

        return app()->make(AwsCognitoClient::class)->setUserAttributes($request[$userKey], $attributes);
    }

    //Function ends
} //Trait ends
