<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\KeysCommand;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Keys\KeyUseRebuilder;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:keys`: `--rebuild-uses` adds the key uses
 * missing from the verified entries, prints what it read and added, never an
 * owner, and exits 0; with `--dry-run` it adds nothing; a failure exits 1
 * printing its class and never its message; and without `--rebuild-uses` it
 * exits 2 before any statement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeysCommand::class)]
final class KeysCommandTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string The code a card charge, encrypted under its actor's key, is captured under. */
    private const string CARD = 'billing.card_charged';

    /** @var string What the command printed last. */
    private string $printed = '';

    /**
     * Bind the package's key wrapper and encrypter, define the card charge, and
     * register the command with the console kernel, which keeps the test
     * independent of the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CARD)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new KeysCommand);
    }

    /**
     * The missing key uses are added from the verified entries, printed, and it
     * exits 0; nothing printed names an owner.
     *
     * @return void
     */
    public function testTheMissingKeyUsesAreAdded(): void
    {
        $this->chargeCards(2);
        $this->keyConnection()->table(KeyTables::keyUsesTable())->delete();

        self::assertSame(0, $this->keys(['--rebuild-uses' => true]));
        self::assertSame("Read 2 entries: 2 verified, 0 skipped.\nAdded 2 key uses.\n", $this->printed);
        self::assertSame(2, $this->keyConnection()->table(KeyTables::keyUsesTable())->count());
        self::assertStringNotContainsString('secret-42', $this->printed);
    }

    /**
     * A dry run counts what it would add, adds nothing, and exits 0.
     *
     * @return void
     */
    public function testADryRunAddsNothing(): void
    {
        $this->chargeCards(1);
        $this->keyConnection()->table(KeyTables::keyUsesTable())->delete();

        self::assertSame(0, $this->keys(['--rebuild-uses' => true, '--dry-run' => true]));
        self::assertSame("Read 1 entries: 1 verified, 0 skipped.\nWould add 1 key uses.\n", $this->printed);
        self::assertSame(0, $this->keyConnection()->table(KeyTables::keyUsesTable())->count());
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
        $failure = new \RuntimeException('SQLSTATE[HY000]: entry of secret-42');

        app()->bind(KeyUseRebuilder::class, static fn (): never => throw $failure);

        self::assertSame(1, $this->keys(['--rebuild-uses' => true]));
        self::assertSame("The key-use rebuild failed with RuntimeException.\n", $this->printed);
    }

    /**
     * Without `--rebuild-uses`, a dry run or not, it exits 2 before any
     * statement runs.
     *
     * @return void
     */
    public function testWithoutRebuildUsesItExitsTwoBeforeAnyStatement(): void
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = $query->sql;
        });

        foreach ([[], ['--dry-run' => true]] as $options) {
            self::assertSame(2, $this->keys($options));
            self::assertSame("The --rebuild-uses option is required: it is the only maintenance audit-log:keys runs.\n", $this->printed);
        }

        self::assertCount(0, $statements);
    }

    /**
     * Capture as many charges of a card the owner owns, each encrypted under
     * the owner's key.
     *
     * @param  int  $count
     * @return void
     */
    private function chargeCards(int $count): void
    {
        for ($charge = 1; $charge <= $count; $charge++) {
            AuditLog::event(self::CARD)->by(Reference::of('App\Models\Patient', 'secret-42'))->withProperties(['amount' => '12.00', 'card' => '4242'])->record();
        }
    }

    /**
     * Run the command with the options given, keep what it printed, and return
     * its exit code.
     *
     * @param  array<string, bool>  $options
     * @return int
     */
    private function keys(array $options): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:keys', $options);
        $this->printed = $kernel->output();

        return $exit;
    }
}
