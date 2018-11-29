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
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return true;
    }

    /**
     * Registers a user in the given user pool.
     *
     * @param  string  $username
     * @param  string  $password
     * @param  array  $attributes
     * @return bool
     */
    public function register($username, $password, array $attributes = [])
    {
        try {
            $response = $this->client->signUp([
                'ClientId' => $this->clientId,
                'Password' => $password,
                'SecretHash' => $this->hash($username),
                'UserAttributes' => $this->userAttributes($attributes),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw $e;
        }

        $this->update($username, ['email_verified' => 'true']);

        return (bool) $response['UserConfirmed'];
    }

    /**
     * Update user attributes.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html
     *
     * @param  string  $username
     * @param  array  $attributes
     * @return bool
     */
    public function updateUserAttributes($username, array $attributes)
    {
        $this->client->AdminUpdateUserAttributes([
            'Username' => $username,
            'UserPoolId' => $this->userPoolId,
            'UserAttributes' => $this->userAttributes($attributes),
        ]);

        return true;
    }

    /**
     * Get user by the given username.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @param  string  $username
     * @return mixed
     */
    public function getUser($username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->userPoolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        dd($user->toArray());

        return $user;
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

    /**
     * Format attributes in Name/Value array
     *
     * @param  array  $attributes
     * @return array
     */
    protected function userAttributes(array $attributes)
    {
        return array_map(function ($k, $v) {
            return [
                'Name' => $k,
                'Value' => $v,
            ];
        }, array_keys($attributes), $attributes);
    }
}
