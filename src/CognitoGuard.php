<?php

namespace Cuonggt\LaravelCognito;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\UserProvider;
use Symfony\Component\HttpFoundation\Request;

class CognitoGuard extends SessionGuard
{
    /**
     * The client which can talk to AWS Cognito.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $client;

    /**
     * Create a new authentication guard.
     *
     * @param  \Cuonggt\LaravelCognito\CognitoClient  $client
     * @param  string  $name
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Contracts\Session\Session  $session
     * @param  \Symfony\Component\HttpFoundation\Request|null  $request
     * @return void
     */
    public function __construct(CognitoClient  $client,
                                $name,
                                UserProvider $provider,
                                Session $session,
                                Request $request = null)
    {
        $this->client = $client;

        parent::__construct($name, $provider, $session, $request);
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) &&
            $this->provider->validateCredentialsByAwsCognito($this->client, $credentials);
    }
}
