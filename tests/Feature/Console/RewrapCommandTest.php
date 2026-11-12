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
use SineMacula\Laravel\AuditLog\Console\RewrapCommand;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Lifecycle\Rewrapper;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\CountsStatements;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:rewrap`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RewrapCommand::class)]
final class RewrapCommandTest extends TestCase
{
    use CountsStatements, MakesSubjectKeys, ReadsTheTrail;

    /** @var array<string, string> The options of the authority every rewrap is asked for on, unless a test gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'keys.rotate'];

    /** @var string What the command printed last. */
    private string $printed = '';

    /**
     * Freeze the clock, record reports, bind the wrapper, register the command.
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

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new RewrapCommand);
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
     * `--rotate` supersedes every live key, naming no owner, and exits 0.
     *
     * @return void
     */
    public function testARotationIsPrintedAndRecorded(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        self::assertSame(0, $this->rewrap(['--rotate' => true, '--reference' => 'app:ticket-9']));

        $lines = explode("\n", trim($this->printed));

        self::assertCount(2, $lines);
        self::assertMatchesRegularExpression('/\ARewrap [0-9a-f-]{36}: complete\.\z/', $lines[0]);
        self::assertSame(sprintf('Rewrapped 0 keys onto wrapping key %s, superseded 1 and skipped 0, in 1 batches.', $this->keyWrapper()->currentKeyId()), $lines[1]);
        self::assertSame([JournalKind::REWRAP->value, 'app:ticket-9'], [$this->journalRows()[0]['kind'], $this->journalRows()[0]['external_reference']]);
        self::assertCount(1, $this->readRecords('audit_log.keys_rewrapped'));
        self::assertStringNotContainsString('secret-42', $this->printed);
    }

    /**
     * A key failing its signature is skipped by id and the partial run exits 0.
     *
     * @return void
     */
    public function testASkippedKeyIsNamedAndThePartialRunExitsZero(): void
    {
        [$key] = $this->makeSubjectKey(self::owner(), null, 'billing');

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['wrap_key_id' => 'd-0000000000000000', 'hmac' => str_repeat('0', 64)]);

        self::assertSame(0, $this->rewrap());
        self::assertStringContainsString(': partial.', $this->printed);
        self::assertStringContainsString(sprintf('Skipped keys: %s.', $key->id), $this->printed);
    }

    /**
     * A tampered key id that is no UUID is counted, never printed.
     *
     * @return void
     */
    public function testATamperedIdIsCountedAndNeverPrinted(): void
    {
        if ($this->keyConnection()->getDriverName() === 'pgsql') {
            self::markTestSkipped('PostgreSQL\'s uuid column holds nothing but a UUID.');
        }

        [$key] = $this->makeSubjectKey(self::owner(), null, 'billing');

        $row                = (array) $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->first();
        $row['id']          = "\e]0;owned\x07\e[31mforged";
        $row['generation']  = 2;
        $row['wrap_key_id'] = 'd-0000000000000000';

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->insert($row);

        self::assertSame(0, $this->rewrap());
        self::assertStringContainsString(': partial.', $this->printed);
        self::assertStringContainsString('skipped 1,', $this->printed);
        self::assertStringNotContainsString("\e", $this->printed);
        self::assertStringNotContainsString('forged', $this->printed);
    }

    /**
     * A dry run counts what it would do, writes nothing and exits 0.
     *
     * @return void
     */
    public function testADryRunWritesNothing(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        self::assertSame(0, $this->rewrap(['--rotate' => true, '--dry-run' => true]));
        self::assertMatchesRegularExpression('/\ADry run [0-9a-f-]{36}: complete\.\n/', $this->printed);
        self::assertStringContainsString('Would rewrap 0 keys onto wrapping key', $this->printed);
        self::assertStringContainsString('superseded 1', $this->printed);
        self::assertSame([], $this->journalRows());
        self::assertSame([], $this->readRecords('audit_log.keys_rewrapped'));
        self::assertStringNotContainsString('could not be written', $this->printed);
    }

    /**
     * A failure exits 1 and prints its class, never its message.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAFailurePrintsItsClassNotItsMessage(): void
    {
        $failure = new \RuntimeException('SQLSTATE[HY000]: wrapped key secret-42');

        app()->bind(Rewrapper::class, static fn (): never => throw $failure);

        self::assertSame(1, $this->rewrap());
        self::assertSame("The rewrap failed with RuntimeException; the batches it committed stand.\n", $this->printed);
    }

    /**
     * A rewrap whose record could not be written still rewraps and warns.
     *
     * @return void
     */
    public function testAnUnrecordedRewrapWarns(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['keys_rotated']);

        self::assertSame(0, $this->rewrap());
        self::assertStringContainsString('The rewrap\'s audit_log.keys_rewrapped record could not be written; audit-log:reconcile writes it from the journal.', $this->printed);
    }

    /**
     * Rows of `[options, message]`: each malformed option.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'no operator type'     => [['--by-type' => ''], 'The --by-type option is required.'],
            'no reason'            => [['--reason' => ''], 'The --reason option is required.'],
            'a reason that is not' => [['--reason' => 'Rotate!'], 'The --reason option must be'],
            'an operator too long' => [['--by-id' => str_repeat('7', 192)], 'The --by-type and --by-id options must each be 1 to 191 characters'],
        ];
    }

    /**
     * Each refusal exits 2, printing why, before any statement runs.
     *
     * @param  array<string, string>  $given
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusedOptionExitsTwoBeforeAnyStatement(array $given, string $message): void
    {
        $statements = $this->countStatements();

        self::assertSame(2, $this->rewrap($given));
        self::assertStringContainsString($message, $this->printed);
        self::assertCount(0, $statements);
    }

    /**
     * Run the command over the authority's options and return its exit code.
     *
     * @param  array<string, bool|string>  $given
     * @return int
     */
    private function rewrap(array $given = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:rewrap', [...self::AUTHORITY, ...$given]);
        $this->printed = $kernel->output();

        return $exit;
    }

    /**
     * The owner whose key a test makes, which nothing printed may name.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\Patient', 'secret-42');
    }
}
