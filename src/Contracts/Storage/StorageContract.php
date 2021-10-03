<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito\Contracts\Storage;

interface StorageContract
{
    /**
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $minutes
     *
     * @return void
     */
    public function add($key, $value, $minutes);


    /**
     * @param  string  $key
     * @param  mixed  $value
     *
     * @return void
     */
    public function forever($key, $value);


    /**
     * @param  string  $key
     *
     * @return mixed
     */
    public function get($key);


    /**
     * @param  string  $key
     *
     * @return bool
     */
    public function destroy($key);


    /**
     * @return void
     */
    public function flush();
}
