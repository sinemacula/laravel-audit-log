<?php

declare(strict_types = 1);

/**
 * Autoload the package's own classes, and its tests', for phpstan in the qlty
 * sandbox, which installs the analysis stack but not the project.
 *
 * Scanning lets phpstan read these classes, but larastan builds a real
 * instance of a model to read its casts, and that needs the class loaded. The
 * namespaces mirror the `autoload` and `autoload-dev` maps in composer.json.
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
