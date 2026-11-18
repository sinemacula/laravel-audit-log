<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use Tests\Concerns\CreatesSigningInUsers;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\TestCase;

/**
 * End-to-end tests for recording with every code required to be registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordPipeline::class)]
final class StrictRegistrationTest extends TestCase
{
    use CreatesSigningInUsers, CreatesWatchedModels, ReadsTheTrail;

    /** @var string The ability the Gate denies. */
    private const string ABILITY = 'approve-invoice';

    /**
     * Create the users' table, deny an ability and let the viewer read every
     * entry.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createUsersTable();
        $this->bindReading();
        $this->allowEverything();

        Gate::define(self::ABILITY, static fn (): bool => false);
    }

    /**
     * The captured codes and the package's own are recorded under strict
     * registration.
     *
     * @return void
     */
    public function testCapturedAndPackageCodesAreRecorded(): void
    {
        $user = self::newUser('alice@example.com');

        Auth::guard('web')->login($user);
        Gate::forUser($user)->allows(self::ABILITY);
        WatchedInvoice::query()->create(['number' => 'INV-1']);
        AuditLog::trail()->visibleTo($this->viewer())->cursorPaginate();

        self::assertSame(
            ['authentication.signed_in', 'authorization.gate_denied', 'invoice.created', 'audit_log.trail_read'],
            array_values(array_map(static fn (AuditEntry $entry): string => $entry->event, AuditEntry::query()->orderBy('recorded_at')->orderBy('id')->get()->all())),
        );
    }

    /**
     * Require every code to be registered, capture sign-ins and Gate denials,
     * and watch the invoices.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('audit-log.definitions.require_registered', true);
        $config->set('audit-log.capture.gate.enabled', true);
        $config->set('auth.providers.users.model', SigningInUser::class);

        app()->booting(static function (Application $app): void {
            AuditLog::watch(WatchedInvoice::class, as: 'invoice', fields: ['number']);
        });
    }
}
