<?php

use SineMacula\CodingStandards\PhpCsFixerConfig;

return PhpCsFixerConfig::make([
    dirname(__DIR__, 2) . '/src',
    dirname(__DIR__, 2) . '/config',
    dirname(__DIR__, 2) . '/database',
    dirname(__DIR__, 2) . '/tests',
]);
