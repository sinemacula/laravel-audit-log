<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity\Anchors;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Filesystem\Filesystem as Files;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorFactory;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use Tests\TestCase;

/**
 * Feature tests for the anchor factory: the null anchor by default, a disk
 * anchor on the named disk or the default one, under the configured path, for
 * the configured log; a malformed setting that fails closed before any disk is
 * resolved; and settings read again on every anchor made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchorFactory::class)]
final class AnchorFactoryTest extends TestCase
{
    /** @var list<string> The faked disks this test uses. */
    private const array DISKS = ['anchors', 'default-anchors'];

    /** @var string The golden first seal's object under the default path. */
    private const string OBJECT = 'audit-log-anchors/app-eu-1/00000000000000000001-329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6.json';

    /**
     * Delete the faked disks' files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::DISKS as $disk) {
            (new Files)->deleteDirectory(storage_path('framework/testing/disks/' . $disk));
        }

        parent::tearDown();
    }

    /**
     * With no anchor configured, the anchor made is the null anchor, even with
     * every other anchor setting malformed, since it needs none of them.
     *
     * @return void
     */
    public function testTheDefaultIsTheNullAnchor(): void
    {
        self::assertInstanceOf(NullAnchor::class, $this->factory()->make());

        $this->configure(['driver' => 'null', 'disk' => [], 'path' => '../x'], ['log_id' => '-a']);

        self::assertInstanceOf(NullAnchor::class, $this->factory()->make());
    }

    /**
     * The disk driver makes a disk anchor on the named disk, named for that
     * disk and path, that writes under the path for the configured log.
     *
     * @return void
     */
    public function testTheDiskDriverMakesADiskAnchorOnTheNamedDisk(): void
    {
        $disk = Storage::fake('anchors');

        $this->configure(['driver' => 'disk', 'disk' => 'anchors', 'path' => 'evidence/seals'], ['log_id' => 'app-eu-1']);

        $anchor = $this->factory()->make();

        self::assertInstanceOf(DiskAnchor::class, $anchor);
        self::assertSame('disk:' . substr(hash('sha256', "anchors\0evidence/seals"), 0, 16), $anchor->name());

        $anchor->anchor(self::summary());

        $files = $disk->allFiles();

        sort($files);

        self::assertSame([str_replace('audit-log-anchors/', 'evidence/seals/', self::OBJECT), 'evidence/seals/app-eu-1/by-sequence/00000000000000000001'], $files);
    }

    /**
     * Rows of `[disk]`: the settings that name no disk.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideDefaultDisks(): iterable
    {
        yield from [
            'PHP null' => [null],
            'empty'    => [''],
        ];
    }

    /**
     * A disk that is `null` or empty is the default disk, which the anchor
     * writes to and is named for.
     *
     * @param  ?string  $disk
     * @return void
     */
    #[DataProvider('provideDefaultDisks')]
    public function testAnEmptyDiskIsTheDefaultDisk(?string $disk): void
    {
        $default = Storage::fake('default-anchors');

        Storage::fake('anchors');

        app(ConfigRepository::class)->set('filesystems.default', 'default-anchors');

        $this->configure(['driver' => 'disk', 'disk' => $disk], ['log_id' => 'app-eu-1']);

        $anchor = $this->factory()->make();

        $anchor->anchor(self::summary());

        self::assertSame('disk:' . substr(hash('sha256', "default-anchors\0audit-log-anchors"), 0, 16), $anchor->name());
        self::assertTrue($default->exists(self::OBJECT));
        self::assertSame([], Storage::disk('anchors')->allFiles());
    }

    /**
     * Rows of `[anchor settings, integrity settings, message]`: a malformed
     * setting of a disk anchor and the message it fails closed with.
     *
     * @return iterable<string, array{0: array<string, int|list<string>|string|null>, 1: array<string, string|null>, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        $driver = '`audit-log.integrity.anchor.driver` must be `null` or `disk`.';
        $disk   = '`audit-log.integrity.anchor.disk` must be a disk name of 1 to 64 characters, or null or empty for the default disk.';
        $path   = '`audit-log.integrity.anchor.path` must be 1 to 191 characters of path segments of letters, digits,'
            . ' dots, underscores and hyphens, separated by single slashes, with no `.` or `..` segment.';
        $logId = '`audit-log.integrity.log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

        yield from [
            'a driver that is no case' => [['driver' => 'ftp'], [], $driver],
            'a disk that is no name'   => [['driver' => 'disk', 'disk' => ['anchors']], [], $disk],
            'a path that leaves'       => [['driver' => 'disk', 'disk' => 'anchors', 'path' => '../x'], [], $path],
            'a log id that is no path' => [['driver' => 'disk', 'disk' => 'anchors'], ['log_id' => 'a/b'], $logId],
        ];
    }

    /**
     * A malformed setting fails closed with its own message before any disk is
     * resolved, so even a disk that is not configured is never reached.
     *
     * @param  array<string, int|list<string>|string|null>  $anchor
     * @param  array<string, string|null>  $integrity
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMalformedSettingFailsClosed(array $anchor, array $integrity, string $message): void
    {
        app(ConfigRepository::class)->set('filesystems.disks.anchors', null);

        $this->configure($anchor, $integrity);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $this->factory()->make();
    }

    /**
     * A disk that is not configured fails when the anchor is made, never later,
     * when a seal is anchored.
     *
     * @return void
     */
    public function testADiskThatIsNotConfiguredFailsWhenMade(): void
    {
        $this->configure(['driver' => 'disk', 'disk' => 'missing'], ['log_id' => 'app-eu-1']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Disk [missing] does not have a configured driver.');

        $this->factory()->make();
    }

    /**
     * One factory reads the settings again for every anchor it makes, so a
     * changed driver, path or log takes effect on the next one.
     *
     * @return void
     */
    public function testEveryResolutionReadsTheSettingsAgain(): void
    {
        $disk    = Storage::fake('anchors');
        $factory = $this->factory();

        $none = $factory->make();

        self::assertInstanceOf(NullAnchor::class, $none);

        $this->configure(['driver' => 'disk', 'disk' => 'anchors'], ['log_id' => 'app-eu-1']);

        $first = $factory->make();

        $this->configure(['path' => 'moved'], ['log_id' => 'app-eu-2']);

        $second = $factory->make();

        self::assertInstanceOf(DiskAnchor::class, $second);
        self::assertNotSame($first->name(), $second->name());
        $summary = new SealSummary('app-eu-2', 1, self::summary()->sealId, self::summary()->sealDigest);

        self::assertSame('moved/app-eu-2/00000000000000000001-' . $summary->sealDigest . '.json', $second->pathOf($summary));
        self::assertSame([], $disk->allFiles());

        $this->configure(['driver' => null], []);

        $again = $factory->make();

        self::assertInstanceOf(NullAnchor::class, $again);
    }

    /**
     * Set the anchor settings and the integrity settings given.
     *
     * @param  array<string, int|list<string>|string|null>  $anchor
     * @param  array<string, string|null>  $integrity
     * @return void
     */
    private function configure(array $anchor, array $integrity): void
    {
        $config = app(ConfigRepository::class);

        foreach ($anchor as $key => $value) {
            $config->set('audit-log.integrity.anchor.' . $key, $value);
        }

        foreach ($integrity as $key => $value) {
            $config->set('audit-log.integrity.' . $key, $value);
        }
    }

    /**
     * The factory, as the container makes it.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorFactory
     */
    private function factory(): AnchorFactory
    {
        return app(AnchorFactory::class);
    }

    /**
     * The summary of the golden first seal.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSummary
     */
    private static function summary(): SealSummary
    {
        return new SealSummary('app-eu-1', 1, '01932b4e-9000-7000-8000-000000000001', '329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6');
    }
}
