<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Trusfin <support@Trusfin.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Trusfin\Cognito\Providers;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Trusfin\Cognito\AwsCognito;
use Trusfin\Cognito\AwsCognitoClient;
use Trusfin\Cognito\AwsCognitoManager;
use Trusfin\Cognito\Guards\CognitoSessionGuard;
use Trusfin\Cognito\Guards\CognitoTokenGuard;
use Trusfin\Cognito\Http\Parser\AuthHeaders;
use Trusfin\Cognito\Http\Parser\Parser;

/**
 * Class AwsCognitoServiceProvider.
 */
class AwsCognitoServiceProvider extends ServiceProvider
{
    /**
     * Register the application services.
     */
    public function register()
    {
        //Register Alias
        $this->registerAliases();
    }

    //Function ends

    public function boot()
    {
        //Configuration path
        $path = realpath(__DIR__.'/../../config/config.php');

        //Publish config
        $this->publishes([
            $path => config_path('cognito.php'),
        ], 'config');

        //Register configuration
        $this->mergeConfigFrom($path, 'cognito');

        $this->registerPolicies();

        //Register facades
        $this->registerCognitoFacades();

        //Set Singleton Class
        $this->registerCognitoProvider();

        //Set Guards
        $this->extendWebAuthGuard();
        $this->extendApiAuthGuard();
    }

    //Function ends

    /**
     * Bind some aliases.
     */
    protected function registerAliases()
    {
        $this->app->alias('trusfin.aws.cognito', AwsCognito::class);
    }

    /**
     * Register Cognito Facades.
     */
    protected function registerCognitoFacades()
    {
        //Request Parser
        $this->app->singleton('trusfin.aws.cognito.parser', function (Application $app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders(),
                    // new QueryString,
                    // new InputSource,
                    // new RouteParams,
                    // new Cookies($this->config('decrypt_cookies')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });

        //Storage Provider
        $this->app->singleton('trusfin.aws.cognito.provider.storage', function (Application $app) {
            return new StorageProvider(
                config('cognito.storage_provider')
            );
        });

        //Aws Cognito Manager
        $this->app->singleton('trusfin.aws.cognito.manager', function (Application $app) {
            return new AwsCognitoManager(
                $app['trusfin.aws.cognito.provider.storage']
            );
        });

        $this->app->singleton('trusfin.aws.cognito', function (Application $app, array $config) {
            return new AwsCognito(
                $app['trusfin.aws.cognito.manager'],
                $app['trusfin.aws.cognito.parser']
            );
        });
    }

    //Function ends

    /**
     * Register Cognito Provider.
     */
    protected function registerCognitoProvider()
    {
        $this->app->singleton(AwsCognitoClient::class, function (Application $app) {
            $aws_config = [
                'region' => config('cognito.region'),
                'version' => config('cognito.version'),
            ];

            //Set AWS Credentials
            $credentials = config('cognito.credentials');
            if (!empty($credentials['key']) && !empty($credentials['secret'])) {
                $aws_config['credentials'] = Arr::only($credentials, ['key', 'secret', 'token']);
            } //End if

            return new AwsCognitoClient(
                new CognitoIdentityProviderClient($aws_config),
                config('cognito.app_client_id'),
                config('cognito.app_client_secret'),
                config('cognito.user_pool_id')
            );
        });
    }

    //Function ends

    /**
     * Extend Cognito Web/Session Auth.
     */
    protected function extendWebAuthGuard()
    {
        Auth::extend('cognito-session', function (Application $app, $name, array $config) {
            $guard = new CognitoSessionGuard(
                $name,
                $client = $app->make(AwsCognitoClient::class),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );

            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }

    //Function ends

    /**
     * Extend Cognito Api Auth.
     */
    protected function extendApiAuthGuard()
    {
        Auth::extend('cognito-token', function (Application $app, $name, array $config) {
            $guard = new CognitoTokenGuard(
                $app['trusfin.aws.cognito'],
                $client = $app->make(AwsCognitoClient::class),
                $app['request'],
                Auth::createUserProvider($config['provider'])
            );

            $guard->setRequest($app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }

    //Function ends
} //Class ends
