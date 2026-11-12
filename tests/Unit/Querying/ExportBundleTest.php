<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Querying\ExportBundle;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the offline bundle published beside an export.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportBundle::class)]
final class ExportBundleTest extends TestCase
{
    /** @var int How many lines the export of every test holds. */
    private const int LINES = 2;

    /**
     * The bundle is the canonical encoding of its fields plus a line feed.
     *
     * @return void
     */
    public function testTheBundleHoldsTheManifestTheSignedEnvelopeAndTheDescriptor(): void
    {
        [$descriptor, $columns, $manifest] = self::export();

        $expected = '{"bundle_version":1,"descriptor":{"artifact_id":"' . $descriptor['artifact_id'] . '","count":2,"digest":"' . $descriptor['digest'] . '","kind":"export"}'
            . ',"entry":' . CanonicalEncoder::encode($columns)
            . ',"manifest":' . json_encode($manifest, CanonicalEncoder::JSON_FLAGS) . "}\n";

        self::assertSame($expected, ExportBundle::encode($descriptor, $columns, $manifest));
    }

    /**
     * A bundle round trips, each column encoding to its signed bytes.
     *
     * @return void
     */
    public function testItRoundTrips(): void
    {
        [$descriptor, $columns, $manifest] = self::export();

        $bundle  = ExportBundle::encode($descriptor, $columns, $manifest);
        $decoded = ExportBundle::decode($bundle);

        self::assertNotNull($decoded);
        self::assertSame($descriptor, $decoded['descriptor']);
        self::assertSame($manifest, $decoded['manifest']);
        self::assertSame(CanonicalEncoder::encode($columns), CanonicalEncoder::encode($decoded['entry']));
        self::assertEqualsCanonicalizing(array_keys($columns), array_keys($decoded['entry']));
        self::assertSame($bundle, ExportBundle::encode($decoded['descriptor'], $decoded['entry'], $decoded['manifest']));
    }

    /**
     * An empty JSON object stays an object, so the signed bytes still match.
     *
     * @return void
     */
    public function testAnEmptyObjectStaysAnObject(): void
    {
        [$descriptor, $columns, $manifest] = self::export();

        $columns['context'] = new \stdClass;

        $decoded = ExportBundle::decode(ExportBundle::encode($descriptor, $columns, $manifest));

        self::assertNotNull($decoded);
        self::assertEquals(new \stdClass, $decoded['entry']['context']);
        self::assertStringContainsString('"context":{}', CanonicalEncoder::encode($decoded['entry']));
    }

    /**
     * The malformed rows' fields encode to the export's own bundle.
     *
     * @return void
     */
    public function testTheRowsAreBuiltFromABundle(): void
    {
        [$descriptor, $columns, $manifest] = self::export();

        $bundle = ExportBundle::encode($descriptor, $columns, $manifest);

        self::assertSame($bundle, self::canonical(self::fields($descriptor, $columns, $manifest)));
        self::assertNotNull(ExportBundle::decode(self::canonical(self::fields($descriptor, $columns, $manifest))));
    }

    /**
     * Rows of `[contents]`: anything but exactly a bundle this release writes.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedBundles(): iterable
    {
        [$descriptor, $columns, $manifest] = self::export();

        $bundle = ExportBundle::encode($descriptor, $columns, $manifest);
        $fields = self::fields($descriptor, $columns, $manifest);

        $wrongCount = $fields;

        $wrongCount['descriptor']['count'] = '2';

        $shortDescriptor = $fields;

        unset($shortDescriptor['descriptor']['kind']);

        $longDescriptor = $fields;

        $longDescriptor['descriptor']['entry_id'] = $fields['descriptor']['artifact_id'];

        yield from [
            'an extra key'                 => [self::canonical([...$fields, 'signed' => true])],
            'a key missing'                => [self::canonical(array_diff_key($fields, ['entry' => true]))],
            'version 2'                    => [self::canonical([...$fields, 'bundle_version' => 2])],
            'the version as a string'      => [self::canonical([...$fields, 'bundle_version' => '1'])],
            'non-canonical spacing'        => [str_replace('"bundle_version":1', '"bundle_version": 1', $bundle)],
            'keys out of order'            => [json_encode(array_reverse($fields), CanonicalEncoder::JSON_FLAGS) . "\n"],
            'no final line feed'           => [substr($bundle, 0, -1)],
            'two final line feeds'         => [$bundle . "\n"],
            'a carriage return and feed'   => [substr($bundle, 0, -1) . "\r\n"],
            'the manifest not a string'    => [self::canonical([...$fields, 'manifest' => ['export_manifest_version' => 1]])],
            'the entry not an object'      => [self::canonical([...$fields, 'entry' => array_values($columns)])],
            'the entry an empty list'      => [self::canonical([...$fields, 'entry' => []])],
            'the descriptor a list'        => [self::canonical([...$fields, 'descriptor' => array_values($descriptor)])],
            'the descriptor short a key'   => [self::canonical($shortDescriptor)],
            'the descriptor with an extra' => [self::canonical($longDescriptor)],
            'the count a string'           => [self::canonical($wrongCount)],
            'a float'                      => [str_replace('"bundle_version":1', '"bundle_version":1.0', $bundle)],
            'not JSON'                     => ["not json\n"],
            'a JSON list'                  => ["[]\n"],
            'a JSON string'                => ["\"bundle\"\n"],
            'empty'                        => [''],
            'a line feed alone'            => ["\n"],
        ];
    }

    /**
     * Each malformed bundle decodes to `null`, never throwing.
     *
     * @param  string  $contents
     * @return void
     */
    #[DataProvider('provideMalformedBundles')]
    public function testDecodeRefusesAnythingElse(string $contents): void
    {
        self::assertNull(ExportBundle::decode($contents));
    }

    /**
     * A bundle at the bound is written and read, and one byte more is refused.
     *
     * @return void
     */
    public function testTheBoundIsTheEnvelopes(): void
    {
        self::withMemory(static function (): void {

            [$descriptor, $columns] = self::export();

            $base = strlen(ExportBundle::encode($descriptor, $columns, ''));
            $fits = ExportBundle::encode($descriptor, $columns, str_repeat('m', EnvelopeCodec::MAX_BYTES - $base));

            self::assertSame(EnvelopeCodec::MAX_BYTES, strlen($fits));
            self::assertNotNull(ExportBundle::decode($fits));

            $over = substr($fits, 0, -2) . 'm' . substr($fits, -2);

            unset($fits);

            self::assertSame(EnvelopeCodec::MAX_BYTES + 1, strlen($over));
            self::assertNull(ExportBundle::decode($over));

            unset($over);

            try {
                ExportBundle::encode($descriptor, $columns, str_repeat('m', EnvelopeCodec::MAX_BYTES - $base + 1));
                self::fail('Expected a bundle over the bound to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('An export bundle must be at most %d bytes.', EnvelopeCodec::MAX_BYTES), $exception->getMessage());
            }
        });
    }

    /**
     * Rows of `[descriptor]`: anything but the four keys, each of its kind.
     *
     * @return iterable<string, array{0: array<string, int|string>}>
     */
    public static function provideMalformedDescriptors(): iterable
    {
        [$descriptor] = self::export();

        yield from [
            'a key missing'      => [array_diff_key($descriptor, ['digest' => true])],
            'an extra key'       => [[...$descriptor, 'entry_id' => 'x']],
            'the count a string' => [[...$descriptor, 'count' => '2']],
            'the kind a number'  => [[...$descriptor, 'kind' => 3]],
            'none'               => [[]],
        ];
    }

    /**
     * A bundle is never written with a malformed descriptor.
     *
     * @param  array<string, int|string>  $descriptor
     * @return void
     */
    #[DataProvider('provideMalformedDescriptors')]
    public function testEncodeRefusesAMalformedDescriptor(array $descriptor): void
    {
        [, $columns, $manifest] = self::export();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An export bundle\'s descriptor holds exactly a string `artifact_id`, an integer `count`, a string `digest` and a string `kind`.');

        ExportBundle::encode($descriptor, $columns, $manifest);
    }

    /**
     * The utility container cannot be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(ExportBundle::class, '__construct'))->isPrivate());
    }

    /**
     * The descriptor, columns and canonical manifest of a two-line export.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{0: array{artifact_id: string, count: int, digest: string, kind: string}, 1: array<string, mixed>, 2: string}
     */
    private static function export(): array
    {
        $manifest = RecordFactory::canonical(ArtifactKind::EXPORT, self::LINES);
        $columns  = RecordFactory::finalisedWithArtifact(ArtifactKind::EXPORT, $manifest, self::LINES)->toArray();

        /** @var array{_audit: array{manifest: array{artifact_id: string, kind: string, digest: string, count: int}}} $properties */
        $properties = $columns['properties'];

        $descriptor = $properties['_audit']['manifest'];

        return [
            ['artifact_id' => $descriptor['artifact_id'], 'count' => $descriptor['count'], 'digest' => $descriptor['digest'], 'kind' => $descriptor['kind']],
            $columns,
            $manifest,
        ];
    }

    /**
     * Run the test with memory for bundles at their bound, then restore it.
     *
     * @param  \Closure(): void  $test
     * @return void
     */
    private static function withMemory(\Closure $test): void
    {
        $original = ini_get('memory_limit');

        ini_set('memory_limit', '1G');

        try {
            $test();
        } finally {
            gc_mem_caches();

            $limit = ini_parse_quantity($original);

            ini_set('memory_limit', $limit < 0 ? $original : (string) max($limit, memory_get_usage(true)));
        }
    }

    /**
     * The bundle's fields as written.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array{artifact_id: string, count: int, digest: string, kind: string}  $descriptor
     * @param  array<string, mixed>  $columns
     * @param  string  $manifest
     * @return array{bundle_version: int, descriptor: array<string, int|string>, entry: \stdClass, manifest: string}
     */
    private static function fields(array $descriptor, array $columns, string $manifest): array
    {
        return ['bundle_version' => 1, 'descriptor' => $descriptor, 'entry' => (object) $columns, 'manifest' => $manifest];
    }

    /**
     * The canonical encoding of the fields plus a line feed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return string
     */
    private static function canonical(array $fields): string
    {
        return CanonicalEncoder::encode($fields) . "\n";
    }
}
