<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\EraseCommand;
use SineMacula\Laravel\AuditLog\Console\PruneCommand;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\TestCase;

/**
 * Integration test for the daily run of seal, prune, erase and strict verify on
 * every engine, through the commands on the default bindings and a disk anchor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealCommand::class)]
#[CoversClass(PruneCommand::class)]
#[CoversClass(EraseCommand::class)]
#[CoversClass(VerifyCommand::class)]
final class DailyWorkflowEnginesTest extends TestCase
{
    /** @var string The code a card charge is captured under, sealing the card for the actor. */
    private const string CHARGE = 'billing.card_charged';

    /** @var string When the charges past thirty days are recorded. */
    private const string OLD = '2026-10-01 10:00:00';

    /** @var string When the recent charge is recorded and the day's run starts. */
    private const string TODAY = '2026-11-15 10:00:00';

    /**
     * Keep thirty days, anchor on a fake disk, and define the charge on the
     * facade.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $config = app(ConfigRepository::class);

        $config->set('audit-log.retention.after_days', 30);
        $config->set('audit-log.integrity.anchor.driver', 'disk');
        $config->set('audit-log.integrity.anchor.disk', 'anchors');

        Storage::fake('anchors');

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CHARGE)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Sealing and anchoring, a prune, an erasure and a second seal leave a log
     * that strict verification passes.
     *
     * @return void
     */
    public function testTheDailyWorkflowPassesStrictVerificationOnEachEngine(): void
    {
        self::at(self::OLD);
        $this->charge('42');
        $this->charge('43');

        self::at(self::TODAY);
        $this->charge('42');

        self::at('2026-11-15 10:05:00');
        $this->command('audit-log:seal');
        $this->command('audit-log:prune');
        $this->command('audit-log:erase', ['type' => 'App\Models\Customer', 'id' => '42', '--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'gdpr.article_17']);

        self::at('2026-11-15 10:10:00');
        $this->command('audit-log:seal');

        $printed = $this->command('audit-log:verify', ['--strict' => true]);

        self::assertMatchesRegularExpression('/^Integrity: 1 valid, 1 pruned, 0 incomplete, 0 unverifiable, 0 tampered\.$/m', $printed);
        self::assertMatchesRegularExpression('/^Anchoring: 2 anchored, 0 unanchored \(0 awaiting their first anchoring\), 0 unavailable, 0 contradicted\.$/m', $printed);
        self::assertMatchesRegularExpression('/^Journal: 5 rows to sequence 5; the latest seal commits to 5\.$/m', $printed);
        self::assertMatchesRegularExpression('/^Keys: 2 verified, 1 erased, 0 findings\.$/m', $printed);
        self::assertStringContainsString('Verification passed.', $printed);

        $last = app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL);

        self::assertSame(['at' => '2026-11-15T10:10:00.000000Z', 'head' => 2, 'passed' => true, 'strict' => true], $last);
    }

    /**
     * Run the command, assert it exits 0, and return what it printed.
     *
     * @param  string  $command
     * @param  array<string, bool|string>  $arguments
     * @return string
     */
    private function command(string $command, array $arguments = []): string
    {
        $exit    = Artisan::call($command, $arguments);
        $printed = Artisan::output();

        self::assertSame(0, $exit, $command . "\n" . $printed);

        return $printed;
    }

    /**
     * Capture a card charge by the customer with the id.
     *
     * @param  string  $customer
     * @return void
     */
    private function charge(string $customer): void
    {
        AuditLog::event(self::CHARGE)
            ->by(Reference::of('App\Models\Customer', $customer))
            ->on(Reference::of('App\Models\Account', '7'))
            ->withProperties(['amount' => '12.00', 'card' => '4242'])
            ->record();
    }

    /**
     * Stop the clock at the time given, in UTC.
     *
     * @param  string  $time
     * @return void
     */
    private function at(string $time): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable($time, 'UTC'));
    }
}
