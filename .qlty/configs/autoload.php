<?php

declare(strict_types = 1);

/**
 * Autoload the package and its tests for phpstan in the qlty sandbox, which
 * installs only the analysis stack; larastan instantiates models to read casts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
spl_autoload_register(static function (string $class): void {
    $root = dirname(__DIR__, 2);

    $namespaces = [
        'SineMacula\\Laravel\\AuditLog\\' => $root . '/src/',
        'Tests\\'                         => $root . '/tests/',
    ];

    foreach ($namespaces as $prefix => $directory) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }

        $file = $directory . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

        if (is_file($file)) {
            require_once $file;
        }

        return;
    }
});
