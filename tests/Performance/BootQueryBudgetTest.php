<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use Tests\TestCase;

/**
 * Performance contract for booting the package: registering it adds no query to
 * a request that records nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class BootQueryBudgetTest extends TestCase
{
    /**
     * A request through a booted application with the package registered issues
     * no queries.
     *
     * @return void
     */
    public function testARequestThatRecordsNothingIssuesNoQueries(): void
    {
        Route::get('/ping', static fn (): string => 'pong');

        DB::enableQueryLog();

        $this->get('/ping')->assertOk()->assertSee('pong');

        self::assertSame([], DB::getQueryLog());
    }
}
