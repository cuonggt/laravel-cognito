<?php

return [
    'region' => env('AWS_COGNITO_REGION', 'us-west-2'),

    'version' => env('AWS_COGNITO_VERSION', 'latest'),

    'app_client_id' => env('AWS_COGNITO_APP_CLIENT_ID'),

    'app_client_secret' => env('AWS_COGNITO_APP_CLIENT_SECRET'),

    'user_pool_id' => env('AWS_COGNITO_USER_POOL_ID'),

    'login_username' => 'email',
];
