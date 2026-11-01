<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection the package's tables live on (`null` for the default).
    | Keep it fixed while the application runs: moving the tables is a deploy,
    | with a migration the application performs and a worker restart.
    |
    */

    'storage' => [
        'connection' => env('AUDIT_LOG_STORAGE_CONNECTION'),
    ],

];
