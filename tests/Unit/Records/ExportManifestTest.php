<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an export's manifest and the plaintexts it reads back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportManifest::class)]
final class ExportManifestTest extends TestCase
{
    /** @var string The first entry exported. */
    private const string FIRST_ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The last entry exported. */
    private const string LAST_ID = '01932b4e-8a40-7000-8000-000000000002';

    /** @var string When the first entry exported was recorded. */
    private const string FIRST_AT = '2026-11-01T12:00:01.000001Z';

    /** @var string When the last entry exported was recorded. */
    private const string LAST_AT = '2026-11-01T12:00:02.000002Z';

    /** @var string The digest of an empty file and of an empty membership. */
    private const string EMPTY_DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    /**
     * The canonical manifest is the canonical encoding of exactly its keys,
     * sorted bytewise.
     *
     * @return void
     */
    public function testTheCanonicalManifestHoldsExactlyItsKeys(): void
    {
        $expected = '{"export_manifest_version":1,"file_sha256":"' . hash('sha256', 'file') . '",'
            . '"first":["' . self::FIRST_AT . '","' . self::FIRST_ID . '"],"format":"ndjson",'
            . '"last":["' . self::LAST_AT . '","' . self::LAST_ID . '"],"lines":2,'
            . '"membership_sha256":"' . self::membership() . '","query_fingerprint":"' . hash('sha256', 'query') . '",'
            . '"scope_fingerprint":"' . hash('sha256', 'scope') . '","snapshot":{"connection":"testing",'
            . '"consistency":"deferred_read_transaction","database":"audit","engine":"sqlite","table":"audit_log_entries"},'
            . '"viewer":{"id":"42","type":"user"}}';

        $canonical = self::canonical();
        $decoded   = json_decode($canonical, true);

        self::assertSame($expected, $canonical);
        self::assertIsArray($decoded);
        self::assertSame(ExportManifest::KEYS, array_keys($decoded));
    }

    /**
     * An export of no line is valid: no first or last position, the empty
     * file's digest, counted as none.
     *
     * @return void
     */
    public function testAZeroLineExportIsValid(): void
    {
        $overrides = ['lines' => 0, 'first' => null, 'last' => null, 'fileSha256' => self::EMPTY_DIGEST, 'membershipSha256' => self::EMPTY_DIGEST];
        $manifest  = self::manifestOf($overrides);

        self::assertSame(ArtifactKind::EXPORT, $manifest->kind);
        self::assertSame(0, $manifest->count);
        self::assertStringContainsString('"first":null', $manifest->canonical);
        self::assertStringContainsString('"last":null', $manifest->canonical);
        self::assertSame(0, ExportManifest::read($manifest->canonical)['count'] ?? null);
    }

    /**
     * The manifest is an `export` artifact counted by its lines and digested as
     * its canonical bytes.
     *
     * @return void
     */
    public function testTheManifestIsAnExportCountedByItsLines(): void
    {
        $manifest = self::manifestOf();

        self::assertSame(ArtifactKind::EXPORT, $manifest->kind);
        self::assertSame(2, $manifest->count);
        self::assertSame(self::canonical(), $manifest->canonical);
        self::assertSame(hash('sha256', $manifest->canonical), $manifest->digest);
    }

    /**
     * Rows of `[lines, first, last]`: positions that are `null` when there are
     * lines, or set when there are none.
     *
     * @return iterable<string, array{0: int, 1: ?array{0: string, 1: string}, 2: ?array{0: string, 1: string}}>
     */
    public static function provideMisplacedPositions(): iterable
    {
        yield from [
            'no first with lines' => [1, null, [self::LAST_AT, self::LAST_ID]],
            'no last with lines'  => [1, [self::FIRST_AT, self::FIRST_ID], null],
            'neither with lines'  => [3, null, null],
            'a first with none'   => [0, [self::FIRST_AT, self::FIRST_ID], null],
            'a last with none'    => [0, null, [self::LAST_AT, self::LAST_ID]],
            'both with none'      => [0, [self::FIRST_AT, self::FIRST_ID], [self::LAST_AT, self::LAST_ID]],
        ];
    }

    /**
     * The first and last positions are both `null` exactly when there are no
     * lines; otherwise the missing position is named.
     *
     * @param  int  $lines
     * @param  ?array{0: string, 1: string}  $first
     * @param  ?array{0: string, 1: string}  $last
     * @return void
     */
    #[DataProvider('provideMisplacedPositions')]
    public function testFirstAndLastAreNullExactlyWhenThereAreNoLines(int $lines, ?array $first, ?array $last): void
    {
        $field = ($lines === 0 ? $first !== null : $first === null) ? 'first' : 'last';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('An export manifest\'s `%s` must be a recorded instant and a lower-case UUID, or `null` exactly when there are no lines.', $field));

        self::canonical(['lines' => $lines, 'first' => $first, 'last' => $last]);
    }

    /**
     * Reading dispatches on the version a manifest names: a version 1 manifest
     * reads as its line count, its digest and its fields exactly as decoded.
     *
     * @return void
     */
    public function testReadDispatchesOnItsVersion(): void
    {
        $canonical = self::canonical();
        $read      = ExportManifest::read($canonical);

        self::assertNotNull($read);
        self::assertSame(2, $read['count']);
        self::assertSame(hash('sha256', $canonical), $read['digest']);
        self::assertSame(json_decode($canonical, true), $read['fields']);
        self::assertSame(1, $read['fields']['export_manifest_version']);
    }

    /**
     * Rows of `[version]`: versions this release does not read, each in an
     * otherwise canonical version 1 manifest.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnsupportedVersions(): iterable
    {
        yield from [
            'version 2'         => ['2'],
            'version 0'         => ['0'],
            'a negative'        => ['-1'],
            'a string'          => ['"1"'],
            'a boolean'         => ['true'],
            'null'              => ['null'],
            'a list of version' => ['[1]'],
        ];
    }

    /**
     * A manifest naming a version this release does not read is not read,
     * whatever else it holds.
     *
     * @param  string  $version
     * @return void
     */
    #[DataProvider('provideUnsupportedVersions')]
    public function testAnUnsupportedVersionIsNotRead(string $version): void
    {
        self::assertNull(ExportManifest::read(str_replace('"export_manifest_version":1', '"export_manifest_version":' . $version, self::canonical())));
    }

    /**
     * A manifest parses by its own version alone, with no container or facade
     * root.
     *
     * @return void
     */
    public function testParsingNeedsNoCatalogue(): void
    {
        $canonical = self::canonical();
        $container = Container::getInstance();
        $facades   = Facade::getFacadeApplication();

        Container::setInstance(new Container);
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        try {
            self::assertSame(2, ExportManifest::read($canonical)['count'] ?? null);
        } finally {
            Container::setInstance($container);
            Facade::setFacadeApplication($facades);
        }
    }

    /**
     * Rows of `[plaintext]`: plaintexts that are not exactly a version 1
     * manifest's canonical form.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonCanonicalPlaintexts(): iterable
    {
        $canonical = self::canonical();
        $empty     = self::canonical(['lines' => 0, 'first' => null, 'last' => null]);
        $replace   = static fn (string $from, string $to, ?string $in = null): string => str_replace($from, $to, $in ?? $canonical);
        $file      = '"file_sha256":"' . hash('sha256', 'file') . '"';
        $names     = '"connection":"testing","consistency":"deferred_read_transaction"';

        yield from [
            'whitespace'             => [$replace('"lines":2', '"lines": 2')],
            'a trailing newline'     => [$canonical . "\n"],
            'reordered keys'         => [$replace('"export_manifest_version":1,' . $file, $file . ',"export_manifest_version":1')],
            'a missing key'          => [$replace(',"format":"ndjson"', '')],
            'an extra key'           => [$replace('"lines":2,', '"lines":2,"limit":5,')],
            'reordered snapshot'     => [$replace($names, '"consistency":"deferred_read_transaction","connection":"testing"')],
            'a snapshot key added'   => [$replace('"table":"audit_log_entries"}', '"table":"audit_log_entries","x":"y"}')],
            'an empty snapshot name' => [$replace('"database":"audit"', '"database":""')],
            'a viewer key added'     => [$replace('"type":"user"}', '"type":"user","x":"y"}')],
            'an empty viewer id'     => [$replace('"id":"42"', '"id":""')],
            'an integer viewer id'   => [$replace('"id":"42"', '"id":42')],
            'an unknown format'      => [$replace('"format":"ndjson"', '"format":"csv"')],
            'a negative line count'  => [$replace('"lines":2', '"lines":-2')],
            'a string line count'    => [$replace('"lines":2', '"lines":"2"')],
            'a float line count'     => [$replace('"lines":2', '"lines":2.0')],
            'an upper-case digest'   => [$replace(hash('sha256', 'file'), strtoupper(hash('sha256', 'file')))],
            'a first with none'      => [$replace('"first":null', '"first":["' . self::FIRST_AT . '","' . self::FIRST_ID . '"]', $empty)],
            'a malformed instant'    => [$replace(self::FIRST_AT, '2026-11-01 12:00:01')],
            'an upper-case id'       => [$replace(self::LAST_ID, strtoupper(self::LAST_ID))],
            'an escaped slash'       => [$replace('"database":"audit"', '"database":"a\/b"')],
            'not JSON'               => [substr($canonical, 0, -1)],
            'a list'                 => ['[1]'],
            'a string'               => ['"export"'],
            'empty'                  => [''],
            'too deep'               => [$replace('"database":"audit"', '"database":["audit"]')],
        ];
    }

    /**
     * Only the canonical form of a version this release reads is read; any
     * other plaintext is `null`, never an exception.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideNonCanonicalPlaintexts')]
    public function testReadRefusesANonCanonicalPlaintext(string $plaintext): void
    {
        self::assertNull(ExportManifest::read($plaintext));
    }

    /**
     * Rows of `[overrides, message]`: values not of their kind, and the refusal
     * each gives.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedValues(): iterable
    {
        $digest   = 'An export manifest\'s `%s` must be 64 lower-case hexadecimal characters.';
        $position = 'An export manifest\'s `%s` must be a recorded instant and a lower-case UUID, or `null` exactly when there are no lines.';
        $snapshot = 'An export manifest\'s `snapshot` must be exactly a non-empty `connection`, `consistency`, `database`, `engine` and `table`.';
        $complete = ['connection' => 'testing', 'consistency' => 'deferred_read_transaction', 'database' => 'audit', 'engine' => 'sqlite', 'table' => 'entries'];

        yield from [
            'an unknown format'            => [['format' => 'csv'], 'An export manifest\'s `format` must be `ndjson`, `ocsf` or `cef`.'],
            'an upper-case format'         => [['format' => 'NDJSON'], 'An export manifest\'s `format` must be `ndjson`, `ocsf` or `cef`.'],
            'an upper-case file digest'    => [['fileSha256' => strtoupper(hash('sha256', 'file'))], sprintf($digest, 'file_sha256')],
            'a short membership digest'    => [['membershipSha256' => substr(self::membership(), 1)], sprintf($digest, 'membership_sha256')],
            'a query fingerprint with LF'  => [['queryFingerprint' => hash('sha256', 'query') . "\n"], sprintf($digest, 'query_fingerprint')],
            'an empty scope fingerprint'   => [['scopeFingerprint' => ''], sprintf($digest, 'scope_fingerprint')],
            'a negative line count'        => [['lines' => -1], 'An export manifest\'s `lines` must be an integer of at least 0.'],
            'a first in local time'        => [['first' => ['2026-11-01 12:00:01', self::FIRST_ID]], sprintf($position, 'first')],
            'a last without microseconds'  => [['last' => ['2026-11-01T12:00:02Z', self::LAST_ID]], sprintf($position, 'last')],
            'a first on no such date'      => [['first' => ['2026-02-30T12:00:01.000001Z', self::FIRST_ID]], sprintf($position, 'first')],
            'a first id not a UUID'        => [['first' => [self::FIRST_AT, 'inv_0042']], sprintf($position, 'first')],
            'an upper-case last id'        => [['last' => [self::LAST_AT, strtoupper(self::LAST_ID)]], sprintf($position, 'last')],
            'a first of three'             => [['first' => [self::FIRST_AT, self::FIRST_ID, 'x']], sprintf($position, 'first')],
            'a last reversed'              => [['last' => [self::LAST_ID, self::LAST_AT]], sprintf($position, 'last')],
            'a snapshot missing its table' => [['snapshot' => array_diff_key($complete, ['table' => true])], $snapshot],
            'a snapshot with a key added'  => [['snapshot' => [...$complete, 'extra' => 'x']], $snapshot],
            'a snapshot with an empty one' => [['snapshot' => ['engine' => ''] + $complete], $snapshot],
            'a snapshot with an integer'   => [['snapshot' => ['database' => 1] + $complete], $snapshot],
        ];
    }

    /**
     * A value not of its kind is refused, naming the key and what it must be,
     * never the value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $overrides
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testRefusesAMalformedValue(array $overrides, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::canonical($overrides);
    }

    /**
     * Each format the package writes is accepted.
     *
     * @return void
     */
    public function testEachFormatIsAccepted(): void
    {
        foreach (['ndjson', 'ocsf', 'cef'] as $format) {
            self::assertStringContainsString('"format":"' . $format . '"', self::canonical(['format' => $format]), $format);
        }
    }

    /**
     * The version, the versions read and the keys are pinned.
     *
     * @return void
     */
    public function testTheConstantsArePinned(): void
    {
        self::assertSame(1, ExportManifest::VERSION);
        self::assertSame([1], ExportManifest::SUPPORTED_VERSIONS);
        self::assertSame([
            'export_manifest_version', 'file_sha256', 'first', 'format', 'last', 'lines', 'membership_sha256', 'query_fingerprint',
            'scope_fingerprint', 'snapshot', 'viewer',
        ], ExportManifest::KEYS);
    }

    /**
     * The viewer and the plaintext are sensitive parameters.
     *
     * @return void
     */
    public function testTheViewerAndPlaintextAreSensitive(): void
    {
        $parameters = [
            (new \ReflectionMethod(ExportManifest::class, 'canonical'))->getParameters()[1],
            (new \ReflectionMethod(ExportManifest::class, 'manifestOf'))->getParameters()[1],
            (new \ReflectionMethod(ExportManifest::class, 'read'))->getParameters()[0],
        ];

        foreach ($parameters as $parameter) {
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), $parameter->getName());
        }
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ExportManifest::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ExportManifest::class, $instance);
    }

    /**
     * The canonical manifest of a two-line NDJSON export, with the values given
     * in place of its own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $overrides
     * @return string
     */
    private static function canonical(array $overrides = []): string
    {
        /** @phpstan-ignore argument.type */
        return ExportManifest::canonical(...[...self::arguments(), ...$overrides]);
    }

    /**
     * The manifest of a two-line NDJSON export, with the values given in place
     * of its own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $overrides
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     */
    private static function manifestOf(array $overrides = []): Manifest
    {
        /** @phpstan-ignore argument.type */
        return ExportManifest::manifestOf(...[...self::arguments(), ...$overrides]);
    }

    /**
     * The arguments of a two-line NDJSON export, by name.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<string, mixed>
     */
    private static function arguments(): array
    {
        return [
            'format'           => 'ndjson',
            'viewer'           => Reference::of('user', '42'),
            'scopeFingerprint' => hash('sha256', 'scope'),
            'queryFingerprint' => hash('sha256', 'query'),
            'snapshot'         => [
                'connection'  => 'testing',
                'consistency' => 'deferred_read_transaction',
                'database'    => 'audit',
                'engine'      => 'sqlite',
                'table'       => 'audit_log_entries',
            ],
            'lines'            => 2,
            'first'            => [self::FIRST_AT, self::FIRST_ID],
            'last'             => [self::LAST_AT, self::LAST_ID],
            'fileSha256'       => hash('sha256', 'file'),
            'membershipSha256' => self::membership(),
        ];
    }

    /**
     * The membership digest of the two entries exported.
     *
     * @return string
     */
    private static function membership(): string
    {
        return hash('sha256', self::FIRST_ID . "\n" . self::LAST_ID . "\n");
    }
}
