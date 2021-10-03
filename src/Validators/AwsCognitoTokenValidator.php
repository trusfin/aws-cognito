<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito\Validators;

use Trusfin\Cognito\Exceptions\InvalidTokenException;

class AwsCognitoTokenValidator
{
    /**
     * Check the structure of the token.
     *
     * @param  string  $value
     *
     * @return string
     */
    public function check($value)
    {
        return $this->validateStructure($value);
    }

    /**
     * @param  string  $token
     *
     * @throws \Trusfin\Cognito\Exceptions\InvalidTokenException
     *
     * @return string
     */
    protected function validateStructure($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Wrong number of segments');
        } //End if

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new InvalidTokenException('Malformed token');
        }

        return $token;
    } //Function ends
} //Class ends
