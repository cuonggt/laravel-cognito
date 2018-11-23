<?php

namespace Cuonggt\LaravelCognito;

use Illuminate\Support\ServiceProvider;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class LaravelCognitoServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/cognito.php', 'cognito'
        );

        $this->app->singleton(CognitoClient::class, function ($app) {
            return new CognitoClient(
                new CognitoIdentityProviderClient([
                    'credentials' => [
                        'key' => config('services.aws.key'),
                        'secret' => config('services.aws.secret'),
                    ],
                    'region' => config('cognito.region'),
                    'version' => config('cognito.version'),
                ]),
                config('cognito.app_client_id'),
                config('cognito.app_client_secret'),
                config('cognito.user_pool_id')
            );
        });

        $this->app['auth']->provider('cognito', function ($app, array $config) {
            return new CognitoUserProvider($app['hash'], $config['model']);
        });

        $this->app['auth']->extend('cognito', function ($app, $name, array $config) {
            $guard = new CognitoGuard(
                $client = $app->make(CognitoClient::class),
                $name,
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
}
