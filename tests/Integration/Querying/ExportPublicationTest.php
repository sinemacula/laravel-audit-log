<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Exporter;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Integration tests for publishing an export once its journal is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Exporter::class)]
#[CoversClass(ExportFile::class)]
final class ExportPublicationTest extends TestCase
{
    use InteractsWithAuditStore, ReadsTheTrail;

    /** @var string The code of an export's journal. */
    private const string TRAIL_EXPORTED = 'audit_log.trail_exported';

    /** @var string The code of a failed publication's record. */
    private const string EXPORT_PUBLISH_FAILED = 'audit_log.export_publish_failed';

    /** @var int The mode of a directory its owner may read and enter but not write. */
    private const int READ_ONLY = 0500;

    /** @var int The mode of a directory its owner alone may use. */
    private const int PRIVATE = 0700;

    /** @var int The mode of a file its owner alone may read and write. */
    private const int OWNER_ONLY = 0600;

    /** @var string The directory every test exports to, made for it alone. */
    private string $directory = '';

    /**
     * Bind the read path, reveal every entry, seed two and make the directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();
        $this->seedEntries(2);

        $this->directory = uniqid(sys_get_temp_dir() . '/audit-log-publication-', true);

        mkdir($this->directory, self::PRIVATE);
    }

    /**
     * Make the directory writable, remove it, and put the entries table back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (is_dir($this->directory)) {
            chmod($this->directory, self::PRIVATE);
        }

        foreach (glob($this->directory . '/{,.}*', GLOB_BRACE) ?: [] as $path) {
            if (!is_file($path)) {
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
     * A read-only directory fails the publication, records it and refuses.
     *
     * @return void
     */
    public function testAPublicationFailureRecordsPublishFailedAndThrows(): void
    {
        $this->skipWhenAReadOnlyDirectoryIsWritable();

        $this->onJournal(function (): void {
            chmod($this->directory, self::READ_ONLY);
        });

        $this->assertPublicationRefused();

        chmod($this->directory, self::PRIVATE);

        self::assertFileDoesNotExist($this->target());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
        $this->assertPublicationFailureRecorded();

        $left = $this->temporaries();

        self::assertCount(1, $left);
        self::assertSame(self::OWNER_ONLY, fileperms($left[0]) & 0777);
    }

    /**
     * Rows of `[suffix]`: the target and its bundle.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAppearingPaths(): iterable
    {
        yield from [
            'the target' => [''],
            'its bundle' => [ExportFile::MANIFEST_SUFFIX],
        ];
    }

    /**
     * A target or bundle appearing after the journal needs `force` to replace.
     *
     * @param  string  $suffix
     * @return void
     */
    #[DataProvider('provideAppearingPaths')]
    public function testATargetCreatedAfterTheJournalIsNeverReplaced(string $suffix): void
    {
        $appeared = $this->target() . $suffix;
        $other    = $suffix === '' ? $this->target() . ExportFile::MANIFEST_SUFFIX : $this->target();

        $this->onJournal(static function () use ($appeared): void {
            file_put_contents($appeared, 'written by another process');
        });

        $this->assertPublicationRefused();

        self::assertSame('written by another process', file_get_contents($appeared));
        self::assertFileDoesNotExist($other);
        self::assertSame([], $this->temporaries());
        $this->assertPublicationFailureRecorded();
    }

    /**
     * With `force`, a target appearing after the journal is replaced.
     *
     * @return void
     */
    public function testWithForceATargetCreatedAfterTheJournalIsReplaced(): void
    {
        $this->onJournal(function (): void {
            file_put_contents($this->target(), 'written by another process');
        });

        $result = app(AuditTrail::class)->visibleTo($this->viewer())->export($this->target(), ExportFormat::NDJSON, true);

        self::assertSame($result->fileSha256, hash_file('sha256', $this->target()));
        self::assertFileExists($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->temporaries());
        self::assertSame([], $this->readRecords(self::EXPORT_PUBLISH_FAILED));
    }

    /**
     * A journal that cannot be written refuses the export and leaves no file.
     *
     * @return void
     */
    public function testAJournalFailureLeavesNoFile(): void
    {
        $written = null;

        Event::listen(QueryExecuted::class, function (QueryExecuted $query) use (&$written): void {
            if ($query->sql !== 'COMMIT' || $written !== null) {
                return;
            }

            $written = array_map(static fn (string $temporary): int => (int) filesize($temporary), $this->temporaries());

            $this->pointAtProbeTable();
        });

        try {
            app(AuditTrail::class)->visibleTo($this->viewer())->export($this->target());

            self::fail('Expected the export to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $refusal->getMessage());
        }

        self::assertIsArray($written);
        self::assertCount(1, $written);
        self::assertGreaterThan(0, $written[0]);
        self::assertSame([], array_values(array_diff(scandir($this->directory) ?: [], ['.', '..'])));
        self::assertSame(0, $this->probeCount());
    }

    /**
     * Export files stay private to their owner under a permissive umask.
     *
     * @return void
     */
    public function testTheTempFileIsNeverWorldReadable(): void
    {
        $modes = [];

        $this->onJournal(function () use (&$modes): void {
            foreach ($this->temporaries() as $temporary) {
                $modes[] = fileperms($temporary) & 0777;
            }
        });

        $umask = umask(0);

        try {
            app(AuditTrail::class)->visibleTo($this->viewer())->export($this->target());

            self::assertSame(0, umask());
        } finally {
            umask($umask);
        }

        self::assertSame([self::OWNER_ONLY], $modes);
        self::assertSame(self::OWNER_ONLY, fileperms($this->target()) & 0777);
        self::assertSame(self::OWNER_ONLY, fileperms($this->target() . ExportFile::MANIFEST_SUFFIX) & 0777);
    }

    /**
     * Skip when this process can write a read-only directory, as root can.
     *
     * @return void
     */
    private function skipWhenAReadOnlyDirectoryIsWritable(): void
    {
        chmod($this->directory, self::READ_ONLY);

        $probe    = $this->directory . '/probe';
        $writable = @touch($probe);

        chmod($this->directory, self::PRIVATE);

        if (!$writable) {
            return;
        }

        unlink($probe);

        self::markTestSkipped('This process writes into a read-only directory, as one running as root does, so a read-only directory cannot fail a publication.');
    }

    /**
     * Assert exporting to the target is refused as a failed publication.
     *
     * @return void
     */
    private function assertPublicationRefused(): void
    {
        try {
            app(AuditTrail::class)->visibleTo($this->viewer())->export($this->target());

            self::fail('Expected the publication to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::publishFailed(\UnexpectedValueException::class)->getMessage(), $refusal->getMessage());
            self::assertStringNotContainsString($this->directory, $refusal->getMessage());
            self::assertNull($refusal->getPrevious());
        }
    }

    /**
     * Assert the journal is a success and the failed publication follows once.
     *
     * @return void
     */
    private function assertPublicationFailureRecorded(): void
    {
        $journals = $this->readRecords(self::TRAIL_EXPORTED);
        $failures = $this->readRecords(self::EXPORT_PUBLISH_FAILED);

        self::assertCount(1, $journals);
        self::assertCount(1, $failures);
        self::assertSame(['success', 'failure', 'publish_failed', 'audit'], [$journals[0]['outcome'], $failures[0]['outcome'], $failures[0]['reason'], $failures[0]['category']]);
        self::assertSameProperties(['export_entry' => $journals[0]['id'], 'outcome' => 'failure'], self::propertiesOf($failures[0]));
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

    /**
     * The temporary files in the directory.
     *
     * @return list<string>
     */
    private function temporaries(): array
    {
        return glob($this->directory . '/.*.tmp') ?: [];
    }

    /**
     * Run the callback once when an export's journal is stored.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function onJournal(\Closure $callback): void
    {
        $ran = false;

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$ran, $callback): void {
            if ($ran || $event->code !== self::TRAIL_EXPORTED) {
                return;
            }

            $ran = true;

            $callback();
        });
    }
}
