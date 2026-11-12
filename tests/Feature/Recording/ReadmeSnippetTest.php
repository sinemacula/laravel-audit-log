<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubDocument;

/**
 * The README's first snippet is present and records the ambient values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
final class ReadmeSnippetTest extends TestCase
{
    /** @var string The snippet as the README shows it. */
    private const string SNIPPET = <<<'PHP'
        ```php
        use SineMacula\Laravel\AuditLog\Facades\AuditLog;

        AuditLog::record('invoice.approved', subject: $invoice, properties: ['amount' => '1200.00']);
        ```
        PHP;

    /** @var string The guard the auth middleware authenticates on. */
    private const string GUARD = 'token';

    /**
     * The snippet is in the README, exactly.
     *
     * @return void
     */
    public function testTheFirstRecordSnippetIsInTheReadmeVerbatim(): void
    {
        $readme = file_get_contents(dirname(__DIR__, 3) . '/README.md');

        self::assertIsString($readme);
        self::assertStringContainsString(self::SNIPPET, $readme);
    }

    /**
     * The snippet writes one row with what it was given and the ambient values.
     *
     * @return void
     */
    public function testItRunsInAnAuthenticatedRequestAndWritesOneRowWithTheAmbientValues(): void
    {
        $this->withoutExceptionHandling();

        Auth::viaRequest(self::GUARD, static fn (): StubAuthUser => (new StubAuthUser)->forceFill(['id' => 42]));

        Route::post('/invoices/{invoice}/approve', static function (string $invoice): string {
            $invoice = (new StubDocument)->forceFill(['id' => $invoice]);

            AuditLog::record('invoice.approved', subject: $invoice, properties: ['amount' => '1200.00']);

            return 'approved';
        })->name('invoices.approve')->middleware(Authenticate::using(self::GUARD));

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])
            ->withHeader('User-Agent', 'Example/1.0')
            ->post('/invoices/invoice-42/approve')
            ->assertOk();

        $entry = AuditEntry::query()->sole();

        self::assertSame('invoice.approved', $entry->event);
        self::assertSame('success', $entry->outcome);
        self::assertSame(StubDocument::class, $entry->subject_type);
        self::assertSame('invoice-42', $entry->subject_id);
        self::assertSame(['amount' => '1200.00'], $entry->properties);
        self::assertSame(StubAuthUser::class, $entry->actor_type);
        self::assertSame('42', $entry->actor_id);
        self::assertSame(self::GUARD, $entry->guard);
        self::assertSame('203.0.113.7', $entry->ip);
        self::assertSame('Example/1.0', $entry->user_agent);
        self::assertSame('http', $entry->origin);
        self::assertNotNull($entry->request_id);
        self::assertEquals(['method' => 'POST', 'route' => 'invoices.approve'], $entry->context);
    }

    /**
     * Configure the guard the auth middleware authenticates on, as the default.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => self::GUARD]);
        $config->set('auth.defaults.guard', self::GUARD);
    }
}
