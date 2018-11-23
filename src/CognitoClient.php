<?php

namespace Cuonggt\LaravelCognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

class CognitoClient
{
    /**
     * @var \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $userPoolId;

    public function __construct(CognitoIdentityProviderClient $client,
                                $clientId,
                                $clientSecret,
                                $userPoolId)
    {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->userPoolId = $userPoolId;
    }

    /**
     * Attempt to authenticate a user using the given username and password.
     *
     * @see  http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     * @param  string  $username
     * @param  string  $password
     * @return bool
     */
    public function attempt($username, $password)
    {
        try {
            $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->hash($username),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->userPoolId,
            ]);
        } catch (CognitoIdentityProviderException $exception) {
            return false;
        }

        return true;
    }

    /**
     * Creates a HMAC from the given credentials.
     *
     * @param  string  $username
     * @return string
     */
    protected function hash($username)
    {
        return base64_encode(
            hash_hmac(
                'sha256',
                $username.$this->clientId,
                $this->clientSecret,
                true
            )
        );
    }
}
