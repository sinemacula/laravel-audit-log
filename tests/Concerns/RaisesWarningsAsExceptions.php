<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;

/**
 * Raises every warning as an exception, as Laravel does, so a test proves its
 * subject runs quietly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RaisesWarningsAsExceptions
{
    /**
     * Raise every warning as an exception.
     *
     * @return void
     */
    #[Before]
    protected function raiseWarningsAsExceptions(): void
    {
        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });
    }

    /**
     * Restore the error handler after each test.
     *
     * @return void
     */
    #[After]
    protected function restoreTheErrorHandler(): void
    {
        restore_error_handler();
    }
}
