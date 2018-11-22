<?php

namespace Cuonggt\LaravelCognito;

use Illuminate\Support\Arr;
use Cuonggt\LaravelCognito\CognitoClient;
use Illuminate\Auth\EloquentUserProvider;

class CognitoUserProvider extends EloquentUserProvider
{
    /**
     * Validate a user against the given credentials.
     *
     * @param  \Cuonggt\LaravelCognito\CognitoClient  $client
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentialsByAwsCognito(CognitoClient $client, array $credentials)
    {
        $credentials = Arr::only($credentials, [config('cognito.login_username'), 'password']);

        return $client->attempt($credentials[config('cognito.login_username')], $credentials['password']);
    }
}
