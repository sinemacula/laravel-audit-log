<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Console\ExportCommand;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:export`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportCommand::class)]
final class ExportCommandTest extends TestCase
{
    use InteractsWithAuditStore, ReadsTheTrail;

    /** @var string The code of an export's journal. */
    private const string TRAIL_EXPORTED = 'audit_log.trail_exported';

    /** @var string The code of a verification's record. */
    private const string EXPORT_VERIFIED = 'audit_log.export_verified';

    /** @var string The type of the viewer the tests name. */
    private const string VIEWER_TYPE = 'App\Models\User';

    /** @var string The id of the viewer the tests name. */
    private const string VIEWER_ID = '7';

    /** @var string The line a run that names no viewer prints. */
    private const string NO_VIEWER = 'Name the viewer the export is made for with both --viewer-type and --viewer-id.';

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /** @var string What the last run printed. */
    private string $printed = '';

    /**
     * Make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-export-command-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Remove the directory and put the entries table back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [] as $path) {
            if (!is_file($path) && !is_link($path)) {
                continue;
            }

            unlink($path);
        }

        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }

        $this->removeProbeTable();

        parent::tearDown();
    }

    /**
     * An export prints its count, journal entry, digest and bundle.
     *
     * @return void
     */
    public function testItExportsAndPrintsTheJournalAndDigest(): void
    {
        $this->allowEverything();
        $this->seedEntries(3);

        self::assertSame(0, $this->export());

        $journal = $this->readRecords(self::TRAIL_EXPORTED);
        $target  = $this->target();

        self::assertCount(1, $journal);
        self::assertIsString($journal[0]['id']);
        self::assertSame(
            "Exported 3 entries to {$target}.\n"
            . "Journal entry: {$journal[0]['id']} (stored).\n"
            . 'SHA-256: ' . hash_file('sha256', $target) . ".\n"
            . "Manifest: {$target}.manifest.json.\n",
            $this->printed,
        );
        self::assertCount(3, file($target) ?: []);
        self::assertFileExists($target . ExportFile::MANIFEST_SUFFIX);
    }

    /**
     * The viewer is the reference `--viewer-type` and `--viewer-id` name.
     *
     * @return void
     */
    public function testItTakesTheViewerAsTypeAndId(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        self::assertSame(0, $this->export(['--viewer-type' => 'App\Models\Auditor', '--viewer-id' => '0042']));

        $asked = $policy->asked();

        self::assertCount(1, $asked);
        self::assertInstanceOf(Reference::class, $asked[0][0]);
        self::assertSame(['App\Models\Auditor', '0042'], [$asked[0][0]->type, $asked[0][0]->id]);
        self::assertSame(ReadPurpose::EXPORT, $asked[0][1]);

        $journal = $this->readRecords(self::TRAIL_EXPORTED)[0];

        self::assertSame(['App\Models\Auditor', '0042'], [$journal['actor_type'], $journal['actor_id']]);
    }

    /**
     * Rows of `[the options given]`: runs missing either viewer option.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideMissingViewers(): iterable
    {
        yield from [
            'no type'   => [['--viewer-id' => self::VIEWER_ID]],
            'no id'     => [['--viewer-type' => self::VIEWER_TYPE]],
            'no viewer' => [[]],
        ];
    }

    /**
     * Without both viewer options the command is invalid before any read.
     *
     * @param  array<string, string>  $options
     * @return void
     */
    #[DataProvider('provideMissingViewers')]
    public function testWithoutAViewerItRefuses(array $options): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->seedEntry();
        $this->captureQueries();

        self::assertSame(2, $this->runCommand(['file' => $this->target()] + $options));
        self::assertSame(self::NO_VIEWER . "\n", $this->printed);
        $this->assertNothingWasRead($policy);
    }

    /**
     * Rows of `[type, id, the line printed]`: viewers a reference refuses.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideUnreferenceableViewers(): iterable
    {
        $type = 'A reference\'s type must be from 1 to 191 characters, with no control characters.';
        $id   = 'A reference\'s id must be from 1 to 191 characters, with no control characters.';

        yield from [
            'an empty type'          => ['', self::VIEWER_ID, $type],
            'an empty id'            => [self::VIEWER_TYPE, '', $id],
            'a type over its length' => [str_repeat('a', 192), self::VIEWER_ID, $type],
            'a control in the id'    => [self::VIEWER_TYPE, "7\x07", $id],
        ];
    }

    /**
     * An unreferenceable viewer is refused without echoing what was given.
     *
     * @param  string  $type
     * @param  string  $id
     * @param  string  $line
     * @return void
     */
    #[DataProvider('provideUnreferenceableViewers')]
    public function testAnUnreferenceableViewerIsRefused(string $type, string $id, string $line): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->captureQueries();

        self::assertSame(2, $this->export(['--viewer-type' => $type, '--viewer-id' => $id]));
        self::assertSame($line . "\n", $this->printed);
        $this->assertNothingWasRead($policy);
    }

    /**
     * An unknown format is refused before anything is read.
     *
     * @return void
     */
    public function testAnUnknownFormatIsRefused(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        $this->captureQueries();

        self::assertSame(2, $this->export(['--format' => 'NDJSON']));
        self::assertSame("The --format option must be ndjson, ocsf or cef.\n", $this->printed);

        self::assertSame(2, $this->export(['--format' => 'xml', '--verify' => true]));
        self::assertSame("The --format option must be ndjson, ocsf or cef.\n", $this->printed);

        $this->assertNothingWasRead($policy);
    }

    /**
     * An existing file is refused without `--force` and left as it was.
     *
     * @return void
     */
    public function testAnExistingFileIsRefusedWithoutForce(): void
    {
        $policy = $this->usePolicy(static fn (): AccessScope => AccessScope::all());

        file_put_contents($this->target(), 'kept');

        $this->captureQueries();

        self::assertSame(2, $this->export());
        self::assertSame("The export target already exists; pass force to replace it.\n", $this->printed);
        self::assertSame('kept', file_get_contents($this->target()));
        $this->assertNothingWasRead($policy);
    }

    /**
     * A missing target directory is invalid, without naming the path.
     *
     * @return void
     */
    public function testAMissingDirectoryIsRefused(): void
    {
        $this->allowEverything();

        self::assertSame(2, $this->runCommand($this->parametersWith(['file' => $this->directory . '/missing/trail.ndjson'])));
        self::assertSame("The export target's directory does not exist or is not writable.\n", $this->printed);
        self::assertSame([], $this->readRecords());
    }

    /**
     * With `--force` an existing file and bundle are replaced by the export's.
     *
     * @return void
     */
    public function testForceReplacesIt(): void
    {
        $this->allowEverything();
        $this->seedEntry();

        file_put_contents($this->target(), 'old');
        file_put_contents($this->target() . ExportFile::MANIFEST_SUFFIX, 'old');

        self::assertSame(0, $this->export(['--force' => true]));
        self::assertStringStartsWith("Exported 1 entries to {$this->target()}.\n", $this->printed);
        self::assertNotSame('old', file_get_contents($this->target()));
        self::assertNotSame('old', file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));
    }

    /**
     * Verifying an untouched export succeeds once the verification is recorded.
     *
     * @return void
     */
    public function testVerifyExitsZeroForAnUntouchedExport(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        self::assertSame(0, $this->export());
        self::assertSame(0, $this->export(['--verify' => true]));
        self::assertSame("Verified.\n", $this->printed);
        self::assertCount(1, $this->readRecords(self::EXPORT_VERIFIED));
    }

    /**
     * Verifying a tampered export lists each finding in order and fails.
     *
     * @return void
     */
    public function testVerifyExitsOneAndListsTheFindings(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        self::assertSame(0, $this->export());

        file_put_contents($this->target(), str_replace('inv_0042', 'inv_0043', (string) file_get_contents($this->target())));

        self::assertSame(1, $this->export(['--verify' => true]));

        $findings = app(AuditTrail::class)->visibleTo($this->viewer())->verifyExport($this->target())->findings;

        self::assertContains(ExportFinding::FILE_MISMATCH, $findings);
        self::assertContains(ExportFinding::LINE_TAMPERED, $findings);
        self::assertSame(
            implode('', array_map(static fn (ExportFinding $finding): string => $finding->value . "\n", $findings)) . "Not verified.\n",
            $this->printed,
        );
    }

    /**
     * A file with no bundle does not verify, naming the failed steps.
     *
     * @return void
     */
    public function testVerifyingAFileWithNoBundleExitsOne(): void
    {
        $this->allowEverything();

        file_put_contents($this->target(), '');

        self::assertSame(1, $this->export(['--verify' => true]));
        self::assertStringStartsWith(ExportFinding::BUNDLE_MALFORMED->value . "\n", $this->printed);
        self::assertStringEndsWith("Not verified.\n", $this->printed);
    }

    /**
     * An unrecordable read is refused, printing no value, publishing nothing.
     *
     * @return void
     */
    public function testARefusedReadExitsOne(): void
    {
        $this->allowEverything();
        $this->pointAtProbeTable();

        self::assertSame(1, $this->export());
        self::assertSame(AuditReadRefusedException::unrecorded()->getMessage() . "\n", $this->printed);
        self::assertFileDoesNotExist($this->target());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
    }

    /**
     * A verification whose record cannot be written is refused the same way.
     *
     * @return void
     */
    public function testARefusedVerificationExitsOne(): void
    {
        $this->allowEverything();
        $this->seedEntry();

        self::assertSame(0, $this->export());

        $this->pointAtProbeTable();

        self::assertSame(1, $this->export(['--verify' => true]));
        self::assertSame(AuditReadRefusedException::unrecorded()->getMessage() . "\n", $this->printed);
    }

    /**
     * Under the default policy a viewer gets an empty export and success.
     *
     * @return void
     */
    public function testADeniedViewerGetsAnEmptyExport(): void
    {
        $this->seedEntries(2);

        self::assertSame(0, $this->export());
        self::assertStringStartsWith("Exported 0 entries to {$this->target()}.\n", $this->printed);
        self::assertSame('', file_get_contents($this->target()));

        $journal = $this->readRecords(self::TRAIL_EXPORTED)[0];

        self::assertSame(['denied', 'no_scope'], [$journal['outcome'], $journal['reason']]);
    }

    /**
     * Rows of `[format]`: every format an export is written in.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat}>
     */
    public static function provideFormats(): iterable
    {
        yield from [
            'NDJSON' => [ExportFormat::NDJSON],
            'OCSF'   => [ExportFormat::OCSF],
            'CEF'    => [ExportFormat::CEF],
        ];
    }

    /**
     * Each format is accepted, written, journalled under its name and verifies.
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return void
     */
    #[DataProvider('provideFormats')]
    public function testEachFormatIsAccepted(ExportFormat $format): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        self::assertSame(0, $this->export(['--format' => $format->value]));

        $journal = $this->readRecords(self::TRAIL_EXPORTED)[0];

        self::assertSame($format->value, self::propertiesOf($journal)['format'] ?? null);
        self::assertCount(2, file($this->target()) ?: []);
        self::assertSame(0, $this->export(['--verify' => true]));
    }

    /**
     * A path holding what would read as a style is printed as it is.
     *
     * @return void
     */
    public function testThePathIsPrintedAsItIs(): void
    {
        $this->allowEverything();

        $target = $this->directory . '/<error>trail.ndjson';

        self::assertSame(0, $this->runCommand($this->parametersWith(['file' => $target])));
        self::assertStringStartsWith("Exported 0 entries to {$target}.\n", $this->printed);
        self::assertStringEndsWith("Manifest: {$target}.manifest.json.\n", $this->printed);
    }

    /**
     * What an access policy throws is not caught as a refusal.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testAThrowingPolicyIsNotCaught(): void
    {
        $thrown = new \RuntimeException('The directory could not be reached.');

        $this->usePolicy(static fn (): AccessScope => throw $thrown);

        try {
            $this->export();

            self::fail('Expected what the policy threw to propagate.');
        } catch (\RuntimeException $propagated) {
            self::assertSame($thrown, $propagated);
        }
    }

    /**
     * An invalid argument the target did not raise is not caught.
     *
     * @return void
     */
    public function testAnotherInvalidArgumentIsNotCaught(): void
    {
        $this->allowEverything();

        app(ConfigRepository::class)->set('audit-log.storage.connection', 'nowhere');

        try {
            $this->export();

            self::fail('Expected the invalid argument to propagate.');
        } catch (\InvalidArgumentException $propagated) {
            self::assertStringNotContainsString('export target', $propagated->getMessage());
        } finally {
            app(ConfigRepository::class)->set('audit-log.storage.connection', null);
        }
    }

    /**
     * The command's name, options and NDJSON default are pinned.
     *
     * @return void
     */
    public function testTheSignatureIsPinned(): void
    {
        $command    = new ExportCommand;
        $definition = $command->getDefinition();

        self::assertSame('audit-log:export', $command->getName());
        self::assertSame(['file'], array_keys($definition->getArguments()));
        self::assertTrue($definition->getArgument('file')->isRequired());
        self::assertSame(['viewer-type', 'viewer-id', 'format', 'force', 'verify'], array_keys($definition->getOptions()));
        self::assertTrue($definition->getOption('viewer-type')->acceptValue());
        self::assertTrue($definition->getOption('viewer-id')->acceptValue());
        self::assertSame('ndjson', $definition->getOption('format')->getDefault());
        self::assertFalse($definition->getOption('force')->acceptValue());
        self::assertFalse($definition->getOption('verify')->acceptValue());
    }

    /**
     * Assert nothing was read, written or recorded and the policy unasked.
     *
     * @param  \Tests\Fixtures\Querying\ClosurePolicy  $policy
     * @return void
     */
    private function assertNothingWasRead(ClosurePolicy $policy): void
    {
        self::assertSame([], $policy->asked());
        self::assertSame([], $this->entryReads());
        self::assertSame([], $this->readRecords());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
    }

    /**
     * Run the command as the tests' viewer and return its exit code.
     *
     * @param  array<string, bool|string>  $options
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function export(array $options = []): int
    {
        return $this->runCommand($this->parametersWith($options));
    }

    /**
     * The target and the tests' viewer, with the options given over them.
     *
     * @param  array<string, bool|string>  $options
     * @return array<string, bool|string>
     */
    private function parametersWith(array $options = []): array
    {
        return $options + ['file' => $this->target(), '--viewer-type' => self::VIEWER_TYPE, '--viewer-id' => self::VIEWER_ID];
    }

    /**
     * Run the command, keep what it printed, and return its exit code.
     *
     * @param  array<string, bool|string>  $parameters
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function runCommand(array $parameters): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $exit          = $kernel->call('audit-log:export', $parameters);
        $this->printed = $kernel->output();

        return $exit;
    }

    /**
     * Where the tests export to.
     *
     * @return string
     */
    private function target(): string
    {
        return $this->directory . '/trail.ndjson';
    }
}
