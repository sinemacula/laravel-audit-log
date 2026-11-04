<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;
use SineMacula\Laravel\AuditLog\Querying\ExportFile;
use SineMacula\Laravel\AuditLog\Querying\MembershipDigest;
use Tests\Fixtures\Querying\NoLinkStreamWrapper;

/**
 * Unit tests for the file an export is written to: its temporary files, created
 * exclusively and private to their owner under a umask that is put back, the
 * targets it refuses, the digests and positions its lines keep, and its
 * publication, the bundle first, then the file, never replacing what is there
 * without `force`, refusing a filesystem that cannot hold the hard link that
 * needs, and leaving nothing behind, and a previous export as it was, when it
 * fails.
 *
 * Each test works in a directory of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportFile::class)]
#[CoversClass(MembershipDigest::class)]
final class ExportFileTest extends TestCase
{
    /** @var string The UUID a test fixes every temporary file's name to. */
    private const string UUID = '01932b4e-a000-7000-8000-0000000000aa';

    /** @var string The first exported entry's id. */
    private const string FIRST_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string The second exported entry's id. */
    private const string SECOND_ID = '01932b4e-a000-7000-8000-000000000002';

    /** @var string When the first entry was recorded. */
    private const string FIRST_AT = '2026-11-01T12:00:00.000001Z';

    /** @var string When the second entry was recorded. */
    private const string SECOND_AT = '2026-11-01T12:00:00.000002Z';

    /** @var string The bundle every published export carries. */
    private const string BUNDLE = "{\"bundle_version\":1}\n";

    /** @var string The SHA-256 of no bytes. */
    private const string EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    /** @var string The directory of this test's files. */
    private string $directory = '';

    /** @var int The umask before the test. */
    private int $umask = 0;

    /**
     * Make the test's directory, and keep the umask to put back.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->umask     = umask();
        $this->directory = sys_get_temp_dir() . '/' . uniqid('audit-export-file-', true);

        mkdir($this->directory, 0700);
    }

    /**
     * Put the umask and the UUID factory back, and remove the test's directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        umask($this->umask);

        Str::createUuidsNormally();
        NoLinkStreamWrapper::unregister();

        self::removeDirectory($this->directory);

        parent::tearDown();
    }

    /**
     * Preparing creates a hidden temporary file beside the target, named after
     * it with a UUID, empty and readable and writable by its owner alone, even
     * under a umask that would let everyone read it; the bundle's temporary
     * file is created the same way. Creation is exclusive: a file already at
     * the temporary name is never opened, and the export fails rather than
     * write into it.
     *
     * @return void
     */
    public function testTheTempFileIsCreatedExclusivelyWith0600(): void
    {
        umask(0000);

        $file = ExportFile::prepare($this->target(), false);

        $temps = $this->temps();

        self::assertCount(1, $temps);
        self::assertMatchesRegularExpression('/\A\.trail\.ndjson\.[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.tmp\z/', $temps[0]);
        self::assertSame(0, filesize($this->path($temps[0])));
        self::assertSame(0600, fileperms($this->path($temps[0])) & 0777);

        $file->writeBundle(self::BUNDLE);

        $bundles = array_values(array_filter($this->temps(), static fn (string $temp): bool => str_starts_with($temp, '.trail.ndjson.manifest.json.')));

        self::assertCount(1, $bundles);
        self::assertSame(0600, fileperms($this->path($bundles[0])) & 0777);
        self::assertSame(self::BUNDLE, file_get_contents($this->path($bundles[0])));

        $this->fixTheUuid();

        $squatted = $this->path('.trail.ndjson.' . self::UUID . '.tmp');

        file_put_contents($squatted, 'already here');

        try {
            ExportFile::prepare($this->target(), false);
            self::fail('Expected a file at the temporary name to refuse the export.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s temporary file could not be created.', $exception->getMessage());
        }

        self::assertSame('already here', file_get_contents($squatted));
    }

    /**
     * The umask is put back once the temporary file is open, and also when the
     * open fails.
     *
     * @return void
     */
    public function testTheUmaskIsRestored(): void
    {
        umask(0022);

        ExportFile::prepare($this->target(), false)->writeBundle(self::BUNDLE);

        self::assertSame(0022, umask());

        $this->fixTheUuid();

        touch($this->path('.trail.ndjson.' . self::UUID . '.tmp'));

        try {
            ExportFile::prepare($this->target(), false);
            self::fail('Expected the open to fail.');
        } catch (\UnexpectedValueException) {
            self::assertSame(0022, umask());
        }
    }

    /**
     * Without `force` a target that exists, or a bundle beside it, refuses the
     * export before any file is created.
     *
     * @return void
     */
    public function testAnExistingTargetIsRefusedWithoutForce(): void
    {
        foreach ([$this->target(), $this->target() . ExportFile::MANIFEST_SUFFIX] as $taken) {
            file_put_contents($taken, 'kept');

            try {
                ExportFile::prepare($this->target(), false);
                self::fail('Expected an existing target to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The export target already exists; pass force to replace it.', $exception->getMessage());
            }

            self::assertSame([], $this->temps());
            self::assertSame('kept', file_get_contents($taken));

            unlink($taken);
        }
    }

    /**
     * The target's checks can be made alone, before anything else, creating
     * nothing, and refuse what preparing refuses.
     *
     * @return void
     */
    public function testTheChecksCreateNothing(): void
    {
        ExportFile::check($this->target(), false);

        self::assertSame([], $this->hidden());

        file_put_contents($this->target(), 'kept');

        ExportFile::check($this->target(), true);

        $this->assertRefused(\InvalidArgumentException::class, 'The export target already exists; pass force to replace it.', fn () => ExportFile::check($this->target(), false));
        self::assertSame([], $this->hidden());
    }

    /**
     * A directory whose filesystem cannot hold a hard link, as a FAT volume or
     * an object-store mount cannot, is refused without `force` before anything
     * is made, since such an export could never be published, and the probe
     * leaves nothing behind; with `force`, which renames, it is let through.
     *
     * @return void
     */
    public function testAFilesystemWithoutHardLinksIsRefusedWithoutForce(): void
    {
        NoLinkStreamWrapper::register();

        $target = NoLinkStreamWrapper::wrap($this->target());

        $this->assertRefused(
            \InvalidArgumentException::class,
            'The export target\'s filesystem cannot hold a hard link, so it cannot be published without force.',
            static fn () => ExportFile::check($target, false),
        );

        self::assertSame([], $this->hidden());

        ExportFile::check($target, true);

        self::assertSame([], $this->hidden());
    }

    /**
     * A link that points nowhere still takes the target's place, so it is
     * refused as an existing target.
     *
     * @return void
     */
    public function testADanglingLinkIsAnExistingTarget(): void
    {
        symlink($this->path('nowhere'), $this->target());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The export target already exists; pass force to replace it.');

        ExportFile::prepare($this->target(), false);
    }

    /**
     * With `force` an existing file and bundle are replaced by the export's,
     * and no temporary file is left.
     *
     * @return void
     */
    public function testForceReplacesTheTarget(): void
    {
        file_put_contents($this->target(), 'old file');
        file_put_contents($this->target() . ExportFile::MANIFEST_SUFFIX, 'old bundle');

        $file = ExportFile::prepare($this->target(), true);

        $file->write('{"id":1}', self::FIRST_ID, self::FIRST_AT);
        $file->writeBundle(self::BUNDLE);
        $file->publish(true);

        self::assertSame("{\"id\":1}\n", file_get_contents($this->target()));
        self::assertSame(self::BUNDLE, file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));
        self::assertSame([], $this->hidden());
    }

    /**
     * Each line is written with one line feed; the count, the file's digest,
     * the membership digest and the first and last positions follow the lines
     * written, and the file's digest may be read part way without ending it.
     *
     * @return void
     */
    public function testDigestsAndPositionsFollowTheLines(): void
    {
        $file = ExportFile::prepare($this->target(), false);

        $file->write('first', self::FIRST_ID, self::FIRST_AT);

        self::assertSame(hash('sha256', "first\n"), $file->fileSha256());
        self::assertSame([self::FIRST_AT, self::FIRST_ID], $file->first());
        self::assertSame([self::FIRST_AT, self::FIRST_ID], $file->last());

        $file->write('second', self::SECOND_ID, self::SECOND_AT);

        self::assertSame(2, $file->lines());
        self::assertSame(hash('sha256', "first\nsecond\n"), $file->fileSha256());
        self::assertSame(hash('sha256', "first\nsecond\n"), $file->fileSha256());
        self::assertSame(hash('sha256', self::FIRST_ID . "\n" . self::SECOND_ID . "\n"), $file->membershipSha256());
        self::assertSame([self::FIRST_AT, self::FIRST_ID], $file->first());
        self::assertSame([self::SECOND_AT, self::SECOND_ID], $file->last());

        $file->writeBundle(self::BUNDLE);
        $file->publish(false);

        self::assertSame("first\nsecond\n", file_get_contents($this->target()));
        self::assertSame($file->fileSha256(), hash_file('sha256', $this->target()));
    }

    /**
     * Once the membership digest is taken no line is written, since its id
     * could never be part of it, and the file is left as it was.
     *
     * @return void
     */
    public function testNoLineIsWrittenOnceTheMembershipIsDigested(): void
    {
        $file = ExportFile::prepare($this->target(), false);

        $file->write('first', self::FIRST_ID, self::FIRST_AT);
        $file->membershipSha256();

        try {
            $file->write('second', self::SECOND_ID, self::SECOND_AT);
            self::fail('Expected a line after the membership digest to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A membership digest takes no id once it has been taken.', $exception->getMessage());
        }

        self::assertSame(1, $file->lines());
        self::assertSame(hash('sha256', "first\n"), $file->fileSha256());
    }

    /**
     * Writing the bundle closes the file, which takes no line after it.
     *
     * @return void
     */
    public function testNoLineIsWrittenOnceTheBundleIs(): void
    {
        $file = $this->written($this->target(), false);

        $this->assertRefused(\LogicException::class, 'An export takes no line once its file is closed.', static fn () => $file->write('more', self::SECOND_ID, self::SECOND_AT));

        $file->publish(false);

        self::assertSame("first\n", file_get_contents($this->target()));
    }

    /**
     * An export of no line publishes an empty file, whose digest and membership
     * digest are each the SHA-256 of no bytes, with no first or last position.
     *
     * @return void
     */
    public function testAZeroLineFileIsEmptyWithTheEmptySetDigest(): void
    {
        $file = ExportFile::prepare($this->target(), false);

        $file->writeBundle(self::BUNDLE);
        $file->publish(false);

        self::assertSame(0, $file->lines());
        self::assertSame(self::EMPTY_SHA256, $file->fileSha256());
        self::assertSame(self::EMPTY_SHA256, $file->membershipSha256());
        self::assertNull($file->first());
        self::assertNull($file->last());
        self::assertSame('', file_get_contents($this->target()));
    }

    /**
     * Publication puts the bundle at `<target>.manifest.json` and the file at
     * the target, each still private to its owner, and leaves no temporary
     * file. The bundle goes first: when the file's place is taken, the step
     * that fails is the file's, and the bundle this publication placed is
     * removed again.
     *
     * @return void
     */
    public function testPublishPublishesTheBundleThenTheFile(): void
    {
        $file = $this->written($this->target(), false);

        $file->publish(false);

        self::assertSame("first\n", file_get_contents($this->target()));
        self::assertSame(self::BUNDLE, file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));
        self::assertSame(0600, fileperms($this->target()) & 0777);
        self::assertSame(0600, fileperms($this->target() . ExportFile::MANIFEST_SUFFIX) & 0777);
        self::assertSame([], $this->temps());

        $other = $this->written($this->path('other.ndjson'), false);

        file_put_contents($this->path('other.ndjson'), 'appeared');

        try {
            $other->publish(false);
            self::fail('Expected the publication to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s file could not be published.', $exception->getMessage());
        }

        self::assertFileDoesNotExist($this->path('other.ndjson' . ExportFile::MANIFEST_SUFFIX));
    }

    /**
     * A publication that fails at its first step removes both temporary files
     * and publishes nothing, leaving what took the bundle's place as it was.
     *
     * @return void
     */
    public function testAFailedPublicationRemovesBothTemps(): void
    {
        $file = $this->written($this->target(), false);

        file_put_contents($this->target() . ExportFile::MANIFEST_SUFFIX, 'appeared');

        try {
            $file->publish(false);
            self::fail('Expected the publication to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s bundle could not be published.', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }

        self::assertSame([], $this->temps());
        self::assertFileDoesNotExist($this->target());
        self::assertSame('appeared', file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));
    }

    /**
     * A target that appears after the export was prepared is never replaced
     * without `force`: the file's step fails, the target keeps what it holds,
     * the bundle this publication placed is removed, and so are both temporary
     * files.
     *
     * @return void
     */
    public function testATargetThatAppearsBeforePublicationIsNeverReplacedWithoutForce(): void
    {
        $file = $this->written($this->target(), false);

        file_put_contents($this->target(), 'appeared');

        try {
            $file->publish(false);
            self::fail('Expected the publication to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s file could not be published.', $exception->getMessage());
        }

        self::assertSame('appeared', file_get_contents($this->target()));
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->temps());
    }

    /**
     * With `force`, a step that fails, here the file's, whose place became a
     * directory, removes the bundle this publication placed and both temporary
     * files.
     *
     * @return void
     */
    public function testAFailedForcedPublicationRemovesWhatItPlaced(): void
    {
        $file = $this->written($this->target(), true);

        mkdir($this->target());
        touch($this->target() . '/inside');

        try {
            $file->publish(true);
            self::fail('Expected the publication to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s file could not be published.', $exception->getMessage());
        }

        self::assertDirectoryExists($this->target());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->hidden());
    }

    /**
     * With `force`, a step that fails over a previous export, here the file's,
     * whose place became a directory after the old file was removed, puts the
     * previous bundle back as it was, so the export it describes still
     * verifies, and leaves no temporary or set-aside file.
     *
     * @return void
     */
    public function testAFailedForcedPublicationKeepsThePreviousBundle(): void
    {
        file_put_contents($this->target(), 'old file');
        file_put_contents($this->target() . ExportFile::MANIFEST_SUFFIX, 'old bundle');

        $file = $this->written($this->target(), true);

        unlink($this->target());
        mkdir($this->target());

        try {
            $file->publish(true);
            self::fail('Expected the publication to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s file could not be published.', $exception->getMessage());
        }

        self::assertDirectoryExists($this->target());
        self::assertSame('old bundle', file_get_contents($this->target() . ExportFile::MANIFEST_SUFFIX));
        self::assertSame([], $this->hidden());
    }

    /**
     * With `force`, a bundle step that fails over a previous export leaves the
     * previous file and bundle exactly as they were.
     *
     * @return void
     */
    public function testAFailedForcedBundleStepKeepsThePreviousExport(): void
    {
        file_put_contents($this->target(), 'old file');
        mkdir($this->target() . ExportFile::MANIFEST_SUFFIX);

        $file = $this->written($this->target(), true);

        try {
            $file->publish(true);
            self::fail('Expected the publication to fail.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('The export\'s bundle could not be published.', $exception->getMessage());
        }

        self::assertSame('old file', file_get_contents($this->target()));
        self::assertDirectoryExists($this->target() . ExportFile::MANIFEST_SUFFIX);
        self::assertSame([], $this->hidden());
    }

    /**
     * Discarding removes both temporary files and publishes nothing; it is
     * idempotent, and the export takes no line, bundle or publication after it.
     *
     * @return void
     */
    public function testDiscardRemovesTheTemps(): void
    {
        $file = $this->written($this->target(), false);

        self::assertCount(2, $this->temps());

        $file->discard();
        $file->discard();

        self::assertSame([], $this->temps());
        self::assertFileDoesNotExist($this->target());
        self::assertFileDoesNotExist($this->target() . ExportFile::MANIFEST_SUFFIX);

        $this->assertRefused(\LogicException::class, 'An export takes no line once its file is closed.', static fn () => $file->write('more', self::SECOND_ID, self::SECOND_AT));
        $this->assertRefused(\LogicException::class, 'An export\'s bundle is written once, before it is published.', static fn () => $file->writeBundle(self::BUNDLE));
        $this->assertRefused(\LogicException::class, 'An export is published once, with its bundle written.', static fn () => $file->publish(false));
    }

    /**
     * Discarding before any bundle is written removes the file's temporary file
     * alone.
     *
     * @return void
     */
    public function testDiscardBeforeTheBundle(): void
    {
        ExportFile::prepare($this->target(), false)->discard();

        self::assertSame([], $this->temps());
    }

    /**
     * Once published, discarding removes nothing, so a published export is
     * never taken back, and nothing is written or published again.
     *
     * @return void
     */
    public function testAPublishedExportIsFinished(): void
    {
        $file = $this->written($this->target(), false);

        $file->publish(false);
        $file->discard();

        self::assertFileExists($this->target());
        self::assertFileExists($this->target() . ExportFile::MANIFEST_SUFFIX);

        $this->assertRefused(\LogicException::class, 'An export takes no line once its file is closed.', static fn () => $file->write('more', self::SECOND_ID, self::SECOND_AT));
        $this->assertRefused(\LogicException::class, 'An export\'s bundle is written once, before it is published.', static fn () => $file->writeBundle(self::BUNDLE));
        $this->assertRefused(\LogicException::class, 'An export is published once, with its bundle written.', static fn () => $file->publish(false));
    }

    /**
     * An export is published only once its bundle is written, and its bundle is
     * written once.
     *
     * @return void
     */
    public function testTheBundleIsWrittenOnceBeforePublication(): void
    {
        $file = ExportFile::prepare($this->target(), false);

        $this->assertRefused(\LogicException::class, 'An export is published once, with its bundle written.', static fn () => $file->publish(false));

        $file->writeBundle(self::BUNDLE);

        $this->assertRefused(\LogicException::class, 'An export\'s bundle is written once, before it is published.', static fn () => $file->writeBundle(self::BUNDLE));
        self::assertCount(2, $this->temps());
    }

    /**
     * A target whose directory does not exist is refused before anything is
     * created.
     *
     * @return void
     */
    public function testAMissingDirectoryIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The export target\'s directory does not exist or is not writable.');

        ExportFile::prepare($this->path('missing/trail.ndjson'), true);
    }

    /**
     * A target whose directory cannot be written to is refused, with or without
     * `force`. A process that writes into a read-only directory (one running as
     * root) cannot show it, so the test is skipped there.
     *
     * @return void
     */
    public function testADirectoryThatIsNotWritableIsRefused(): void
    {
        $locked = $this->path('locked');

        mkdir($locked, 0500);

        if (is_writable($locked)) {
            self::markTestSkipped('This process writes into read-only directories.');
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The export target\'s directory does not exist or is not writable.');

        ExportFile::prepare($locked . '/trail.ndjson', true);
    }

    /**
     * A target that is a directory is refused, even with `force`.
     *
     * @return void
     */
    public function testATargetThatIsADirectoryIsRefused(): void
    {
        mkdir($this->target());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The export target is a directory.');

        ExportFile::prepare($this->target(), true);
    }

    /**
     * An export prepared, with one line and its bundle written.
     *
     * @param  string  $target
     * @param  bool  $force
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportFile
     */
    private function written(string $target, bool $force): ExportFile
    {
        $file = ExportFile::prepare($target, $force);

        $file->write('first', self::FIRST_ID, self::FIRST_AT);
        $file->writeBundle(self::BUNDLE);

        return $file;
    }

    /**
     * Assert the work is refused with the exception and message.
     *
     * @param  class-string<\Throwable>  $class
     * @param  string  $message
     * @param  \Closure(): void  $work
     * @return void
     */
    private function assertRefused(string $class, string $message, \Closure $work): void
    {
        try {
            $work();
            self::fail('Expected the work to be refused.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf($class, $exception);
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * Name every temporary file after the fixed UUID.
     *
     * @return void
     */
    private function fixTheUuid(): void
    {
        Str::createUuidsUsing(static fn () => Uuid::fromString(self::UUID));
    }

    /**
     * The export's target, in the test's directory.
     *
     * @return string
     */
    private function target(): string
    {
        return $this->path('trail.ndjson');
    }

    /**
     * A path in the test's directory.
     *
     * @param  string  $name
     * @return string
     */
    private function path(string $name): string
    {
        return $this->directory . '/' . $name;
    }

    /**
     * The names of every hidden file in the test's directory, sorted: the
     * temporary files, the files a forced publication set aside and the
     * hard-link probe's.
     *
     * @return list<string>
     */
    private function hidden(): array
    {
        $hidden = array_values(array_filter(scandir($this->directory) ?: [], static fn (string $name): bool => $name !== '.' && $name !== '..' && str_starts_with($name, '.')));

        sort($hidden);

        return $hidden;
    }

    /**
     * The names of the temporary files in the test's directory, sorted.
     *
     * @return list<string>
     */
    private function temps(): array
    {
        $temps = array_map(basename(...), glob($this->directory . '/.*.tmp') ?: []);

        sort($temps);

        return $temps;
    }

    /**
     * Remove the directory and everything in it, making each directory writable
     * first.
     *
     * @param  string  $directory
     * @return void
     */
    private static function removeDirectory(string $directory): void
    {
        if (!is_dir($directory) || is_link($directory)) {
            return;
        }

        chmod($directory, 0700);

        foreach (scandir($directory) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $path = $directory . '/' . $name;

            if (is_dir($path) && !is_link($path)) {
                self::removeDirectory($path);

                continue;
            }

            unlink($path);
        }

        rmdir($directory);
    }
}
