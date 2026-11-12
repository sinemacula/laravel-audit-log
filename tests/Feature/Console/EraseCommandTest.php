<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\EraseCommand;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureReapplier;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\CountsStatements;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:erase`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EraseCommand::class)]
final class EraseCommandTest extends TestCase
{
    use CountsStatements, MakesSubjectKeys, ReadsTheTrail;

    /** @var array<string, string> The options of the authority every erasure is asked for on, unless a test gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.erasure'];

    /** @var array{type: string, id: string} The owner every test erases, which nothing printed may name. */
    private const array OWNER = ['type' => 'App\Models\Patient', 'id' => 'secret-42'];

    /** @var string The code a card charge, encrypted under its actor's key, is captured under. */
    private const string CARD = 'billing.card_charged';

    /** @var string What the command printed last. */
    private string $printed = '';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, bind the package's services and register the command.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:00', 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CARD)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new EraseCommand);
    }

    /**
     * Put the clock back and remove the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * An owner is erased, printed by fingerprint and counts, and never named.
     *
     * @return void
     */
    public function testAnOwnerIsErasedAndPrinted(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        self::assertSame(0, $this->erase(['--reference' => 'app:ticket-9']));

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of(self::owner());

        $lines = explode("\n", trim($this->printed));
        $row   = $this->journalRows()[0];

        self::assertCount(4, $lines);
        self::assertMatchesRegularExpression('/\AErasure [0-9a-f-]{36}: complete\.\z/', $lines[0]);
        self::assertSame(sprintf('Journal row %s.', $row['id']), $lines[1]);
        self::assertSame(sprintf('Owner fingerprint %s (key %s).', $fingerprint, $fingerprintKey), $lines[2]);
        self::assertSame('Destroyed 1 keys and kept 0; 0 entries affected.', $lines[3]);
        self::assertSame(['app:ticket-9', 'case.erasure'], [$row['external_reference'], $row['reason']]);
        self::assertCount(1, $this->readRecords('audit_log.subject_erased'));
        self::assertNoOwnerPrinted();
    }

    /**
     * A held erasure exits 1 naming the hold; `--partial` goes ahead.
     *
     * @return void
     */
    public function testABlockRefusesUnlessPartial(): void
    {
        $this->chargeCard();

        $hold = app(AuditLifecycle::class)->hold(HoldScope::all()->categories('billing'), self::authority(), HoldBasis::LEGAL_CLAIM)->hold;

        self::assertSame(1, $this->erase());
        self::assertStringContainsString('The erasure was refused (blocked); nothing was written.', $this->printed);
        self::assertStringContainsString(sprintf('Refused for: held:%s.', $hold->id), $this->printed);
        self::assertNoOwnerPrinted();

        self::assertSame(0, $this->erase(['--partial' => true]));
        self::assertStringContainsString(': partial.', $this->printed);
        self::assertStringContainsString('Destroyed 0 keys and kept 1; 0 entries affected.', $this->printed);
        self::assertStringContainsString(sprintf('Kept for: held:%s.', $hold->id), $this->printed);
    }

    /**
     * Older outbox rows refuse an erasure; `--pending` goes ahead.
     *
     * @return void
     */
    public function testAPendingDeliveryRefusesUnlessAccepted(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $this->chargeCard();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:01', 'UTC'));

        self::assertSame(1, $this->erase());
        self::assertStringContainsString('The erasure was refused (pending_delivery); nothing was written.', $this->printed);
        self::assertStringNotContainsString('Refused for', $this->printed);

        self::assertSame(0, $this->erase(['--pending' => true]));
        self::assertStringContainsString('Accepted outbox rows older than the erasure; their fields are erased with the keys.', $this->printed);
    }

    /**
     * An owner already erased exits 0, naming no journal row.
     *
     * @return void
     */
    public function testAnAlreadyErasedOwnerExitsZero(): void
    {
        self::assertSame(0, $this->erase());
        self::assertSame(0, $this->erase());
        self::assertStringContainsString(': already_erased.', $this->printed);
        self::assertStringNotContainsString('Journal row', $this->printed);
    }

    /**
     * A failure prints its class, never its message, which can carry bindings.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAFailurePrintsItsClassNotItsMessage(): void
    {
        $failure = new \RuntimeException('SQLSTATE[HY000]: owner secret-42');

        app()->bind(Eraser::class, static fn (): never => throw $failure);

        self::assertSame(1, $this->erase());
        self::assertSame("The erasure failed with RuntimeException.\n", $this->printed);
        self::assertNoOwnerPrinted();
    }

    /**
     * An erasure whose record could not be written still erases and warns.
     *
     * @return void
     */
    public function testAnUnrecordedErasureWarns(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['entries_affected']);

        self::assertSame(0, $this->erase());
        self::assertStringContainsString('The erasure\'s audit_log.subject_erased record could not be written; audit-log:reconcile writes it from the journal.', $this->printed);
    }

    /**
     * `--reapply` erases every owner its file names and exits 0.
     *
     * @return void
     */
    public function testAReapplyReconcilesTheRestore(): void
    {
        $path = $this->file([(string) json_encode(self::OWNER), '{"type":"App\\\Models\\\Patient","id":"secret-43"}']);

        self::assertSame(0, $this->command(['--reapply' => $path]));
        self::assertStringContainsString(sprintf('of file %s.', hash_file('sha256', $path)), $this->printed);
        self::assertStringContainsString('Owners 2: 2 erased, 0 already erased, 0 erased in part, 0 refused; 0 lines rejected.', $this->printed);
        self::assertMatchesRegularExpression('/Restore reconciled in journal row [0-9a-f-]{36}, at anchored sequence none\./', $this->printed);
        self::assertNoOwnerPrinted();
    }

    /**
     * A reapply that leaves the restore unreconciled exits 1 and says why.
     *
     * @return void
     */
    public function testAnUnreconciledReapplyExitsOne(): void
    {
        self::assertSame(1, $this->command(['--reapply' => $this->file([(string) json_encode(self::OWNER), 'not json'])]));
        self::assertStringContainsString('1 lines rejected.', $this->printed);
        self::assertStringContainsString('The restore is not reconciled', $this->printed);
    }

    /**
     * A reapply that fails exits 1 and prints its class, never its message.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAReapplyFailurePrintsItsClassNotItsMessage(): void
    {
        $failure = new \RuntimeException('owner secret-42');

        app()->bind(ErasureReapplier::class, static fn (): never => throw $failure);

        self::assertSame(1, $this->command(['--reapply' => $this->file([(string) json_encode(self::OWNER)])]));
        self::assertSame("The reapply failed with RuntimeException.\n", $this->printed);
    }

    /**
     * Rows of `[arguments and options, message]`: each malformed input.
     *
     * @return iterable<string, array{0: array<string, bool|string|null>, 1: string}>
     */
    public static function provideRefusals(): iterable
    {
        $owner = 'The owner must be named by its type and id';
        $alone = 'The --reapply option takes no owner, --partial or --pending';

        yield from [
            'no owner'                => [['type' => null, 'id' => null], $owner],
            'no id'                   => [['id' => null], $owner],
            'an id too long'          => [['id' => str_repeat('s', 192)], $owner],
            'no operator type'        => [['--by-type' => ''], 'The --by-type option is required.'],
            'a reason that is not'    => [['--reason' => 'Erase!'], 'The --reason option must be'],
            'a reference too long'    => [['--reference' => str_repeat('a', 192)], 'The --reference option must be 1 to 191 characters'],
            'a reapply with an owner' => [['--reapply' => 'erasures.ndjson'], $alone],
            'a reapply in part'       => [['type' => null, 'id' => null, '--reapply' => 'erasures.ndjson', '--partial' => true], $alone],
            'a reapply with pending'  => [['type' => null, 'id' => null, '--reapply' => 'erasures.ndjson', '--pending' => true], $alone],
            'a reapply of no file'    => [['type' => null, 'id' => null, '--reapply' => '/nowhere/erasures.ndjson'], 'The --reapply option must name a readable erasures file.'],
            'an empty reapply'        => [['type' => null, 'id' => null, '--reapply' => ''], 'The --reapply option must name a readable erasures file.'],
        ];
    }

    /**
     * Each refusal exits 2, printing why, before any statement runs.
     *
     * @param  array<string, bool|string|null>  $given
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusedArgumentExitsTwoBeforeAnyStatement(array $given, string $message): void
    {
        $statements = $this->countStatements();

        self::assertSame(2, $this->command(array_filter([...self::OWNER, ...self::AUTHORITY, ...$given], static fn (bool|string|null $value): bool => $value !== null)));
        self::assertStringContainsString($message, $this->printed);
        self::assertStringNotContainsString('secret', $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * Assert nothing printed names the owner.
     *
     * @return void
     */
    private function assertNoOwnerPrinted(): void
    {
        self::assertStringNotContainsString(self::OWNER['id'], $this->printed);
        self::assertStringNotContainsString('Patient', $this->printed);
    }

    /**
     * Capture a card charge encrypted under the owner's key.
     *
     * @return void
     */
    private function chargeCard(): void
    {
        AuditLog::event(self::CARD)->by(self::owner())->withProperties(['amount' => '12.00', 'card' => '4242'])->record();
    }

    /**
     * Erase the test owner with the options given and return the exit code.
     *
     * @param  array<string, bool|string>  $options
     * @return int
     */
    private function erase(array $options = []): int
    {
        return $this->command([...self::OWNER, ...self::AUTHORITY, ...$options]);
    }

    /**
     * Run the command over the authority's options and return its exit code.
     *
     * @param  array<string, bool|string>  $given
     * @return int
     */
    private function command(array $given): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:erase', [...self::AUTHORITY, ...$given]);
        $this->printed = $kernel->output();

        return $exit;
    }

    /**
     * Write a file of the lines given, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'erasures-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * The owner every test erases.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of(self::OWNER['type'], self::OWNER['id']);
    }

    /**
     * The authority every hold is placed on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }
}
