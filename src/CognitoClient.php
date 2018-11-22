<?php

namespace Cuonggt\LaravelCognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

class CognitoClient
{
    const PASSWORD_RESET_REQUIRED_EXCEPTION = 'PasswordResetRequiredException';

    const USER_NOT_FOUND_EXCEPTION = 'UserNotFoundException';

    /**
     * @var CognitoIdentityProviderClient
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
    protected $poolId;

    public function __construct(CognitoIdentityProviderClient $client,
                                $clientId,
                                $clientSecret,
                                $poolId)
    {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
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
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->hash($username),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $exception) {
            if ($exception->getAwsErrorCode() === self::PASSWORD_RESET_REQUIRED_EXCEPTION ||
                $exception->getAwsErrorCode() === self::USER_NOT_FOUND_EXCEPTION) {
                return false;
            }

            throw $exception;
        }

        return true;
    }

    /**
     * Creates a HMAC from the given credentials
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
