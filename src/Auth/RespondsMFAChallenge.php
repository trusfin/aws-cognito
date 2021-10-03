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

use App\Models\User;
use Aws\Result as AWSResult;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Trusfin\Cognito\AwsCognito;
use Trusfin\Cognito\AwsCognitoClaim;
use Trusfin\Cognito\AwsCognitoClient;

trait RespondsMFAChallenge
{
    /**
     * The AwsCognito instance.
     *
     * @var \Trusfin\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * RespondsMFAChallenge constructor.
     */
    public function __construct(AwsCognito $cognito)
    {
        $this->cognito = $cognito;
    }

    /**
     * @param mixed $request
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws ValidationException
     */
    public function respondMFAChallenge($request)
    {
        if ($request instanceof Request) {
            $validator = Validator::make($request->all(), $this->rules());

            if ($validator->fails()) {
                throw new ValidationException($validator);
            }

            $request = collect($request->all());
        }

        //Create AWS Cognito Client
        $client = app()->make(AwsCognitoClient::class);

        // get user uuid
        $user = User::where('email', $request['username'])->first();
//        dd($user->uuid);
        //Responds MFA challenge
        $result = $client->respondMFAChallenge($request['session'], $request['challenge_value'], $user->uuid);

        if (is_string($result)) {
            return $response = response()->json(['error' => 'cognito.'.$result], 400);
        }
        if ($result instanceof AWSResult) {
//            $user = User::where('email', $request['username'])->first();
            $claim = new AwsCognitoClaim($result, $user, 'email');
            $this->cognito->setClaim($claim)->storeToken();

            return $result['AuthenticationResult'];
        }

        return $result;
    }

    /**
     * Get the respond to MFA challenge validation rules.
     *
     * @return array
     */
    protected function rules()
    {
        return [
            'session' => 'required',
            'value' => 'required|string',
            'email' => 'required|email',
        ];
    }
}
