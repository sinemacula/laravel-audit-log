<?php

declare(strict_types = 1);

namespace Tests\Unit\Export;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Export\OcsfFormatter;
use Tests\Fixtures\Export\OcsfSchemaBuilder;
use Tests\Fixtures\Export\OcsfValidator;

/**
 * Pins the OCSF schema built from the upstream tag: every file built matches
 * the checksum its provenance records, no file is there that the provenance
 * does not list, the provenance names the tag, its commit and the upstream
 * files read, the version is the formatter's, every file is written in the
 * house layout, every type a class reaches is defined, and no file holds a
 * description or names a third-party product.
 *
 * The classes are not resolved again here: that needs the upstream checkout,
 * which the tests do not have offline. `ocsf/build.php` rebuilds them from a
 * checkout, and the checksums pinned here catch any hand edit since.
 *
 * It covers nothing: it checks test fixtures, not the package's code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PinnedOcsfSchemaTest extends TestCase
{
    /** @var list<string> The files built but for the classes, which `OcsfValidator::CLASSES` names. */
    private const array BUILT = ['LICENSE', 'NOTICE', 'version.json'];

    /** @var list<string> The upstream files every build reads, at least. */
    private const array SOURCES = [
        'LICENSE', 'NOTICE', 'categories.json', 'dictionary.json', 'version.json', 'events/base_event.json', 'events/application/application.json',
        'events/application/api_activity.json',
    ];

    /**
     * Every file the provenance lists is the one built, byte for byte, and it
     * lists exactly the licence, the notice, the version and each class.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEveryBuiltFileMatchesItsChecksum(): void
    {
        $checksums = self::provenance()['generated'];
        $expected  = [...self::BUILT, ...array_map(static fn (string $class): string => $class . '.json', OcsfValidator::CLASSES)];
        $listed    = array_keys($checksums);

        sort($expected);
        sort($listed);

        self::assertSame($expected, $listed);

        foreach ($checksums as $path => $checksum) {
            self::assertSame($checksum, hash_file('sha256', OcsfValidator::ROOT . '/' . $path), $path);
        }
    }

    /**
     * Every file or directory beside the provenance is a file it lists.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNoFileIsUnlisted(): void
    {
        $listed = array_keys(self::provenance()['generated']);
        $files  = array_values(array_diff(scandir(OcsfValidator::ROOT) ?: [], ['.', '..', 'provenance.json']));

        sort($listed);

        self::assertSame($listed, $files);
    }

    /**
     * The provenance names the repository, the tag, the commit the tag points
     * to, the licence, how the files were modified, and the checksum of each
     * upstream file the build read; the licence and the notice are there.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testProvenanceNamesTheTagAndItsCommit(): void
    {
        $provenance = self::provenance();

        self::assertSame('https://github.com/ocsf/ocsf-schema', $provenance['repository']);
        self::assertSame('1.9.0', $provenance['tag']);
        self::assertSame('856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba', $provenance['commit']);
        self::assertSame('Apache-2.0', $provenance['licence']);
        self::assertStringStartsWith('Derived from the upstream files, not copied', $provenance['modified']);

        foreach (self::SOURCES as $path) {
            self::assertArrayHasKey($path, $provenance['sources'], $path);
        }

        foreach ([...$provenance['sources'], ...$provenance['generated']] as $path => $checksum) {
            self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $checksum, $path);
        }

        self::assertStringContainsString('Apache License', (string) file_get_contents(OcsfValidator::ROOT . '/LICENSE'));
        self::assertStringContainsString('Open Cybersecurity Schema Framework', (string) file_get_contents(OcsfValidator::ROOT . '/NOTICE'));
    }

    /**
     * The version file says 1.9.0, which is the version the formatter writes
     * into every event.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheVersionFileSaysTheFormattersVersion(): void
    {
        $version = json_decode((string) file_get_contents(OcsfValidator::ROOT . '/version.json'), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame(['version' => '1.9.0'], $version);
        self::assertSame('1.9.0', OcsfFormatter::VERSION);
    }

    /**
     * Every JSON file is written as the build writes it, pretty-printed with a
     * newline at the end, and every other file ends with a newline.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEveryFileIsInTheHouseLayout(): void
    {
        foreach (self::files() as $path) {
            $contents = (string) file_get_contents(OcsfValidator::ROOT . '/' . $path);

            self::assertStringEndsWith("\n", $contents, $path);

            if (!str_ends_with($path, '.json')) {
                continue;
            }

            self::assertSame(OcsfSchemaBuilder::encode(self::decode($path)), $contents, $path);
        }
    }

    /**
     * Every type an attribute of a class or of an object it reaches has is a
     * type the dictionary defines, an object the class reaches, or the generic
     * object, so leaving a profile out left nothing pointing at an object that
     * is not there.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function testEveryTypeAClassReachesIsDefined(): void
    {
        foreach (OcsfValidator::CLASSES as $class) {
            $schema     = OcsfValidator::schema($class);
            $attributes = [$schema['attributes'], ...array_column($schema['objects'], 'attributes')];
            $types      = array_unique(array_column(array_merge(...$attributes), 'type'));

            sort($types);

            $defined   = [...array_keys($schema['types']), ...array_keys($schema['objects']), 'object'];
            $undefined = array_values(array_diff($types, $defined));

            self::assertSame([], $undefined, $class);
        }
    }

    /**
     * No JSON file holds a `description` key at any depth.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNoFileHoldsADescription(): void
    {
        foreach (self::files() as $path) {
            if (!str_ends_with($path, '.json')) {
                continue;
            }

            self::assertFalse(self::hasKey(self::decode($path), 'description'), $path);
        }
    }

    /**
     * No file names any of the vendors or products the schema's upstream text
     * named, in any case, nor the abbreviation for their field as a word. The
     * names are kept encoded, so this file never holds them either.
     *
     * @return void
     */
    public function testNoFileNamesAThirdPartyProduct(): void
    {
        $patterns = [
            ...array_map(static fn (string $name): string => '/' . str_rot13($name) . '/i', ['naguebcvp', 'pynhqr', 'bcranv', 'tcg']),
            '/(?<![a-z])' . str_rot13('nv') . '(?![a-z])/i',
        ];

        foreach (self::files() as $path) {
            $contents = (string) file_get_contents(OcsfValidator::ROOT . '/' . $path);

            foreach ($patterns as $pattern) {
                self::assertDoesNotMatchRegularExpression($pattern, $contents, $path);
            }
        }
    }

    /**
     * The provenance of the files built.
     *
     * @return array{repository: string, tag: string, commit: string, licence: string, modified: string, sources: array<string, string>, generated: array<string, string>}
     *
     * @throws \JsonException
     */
    private static function provenance(): array
    {
        /** @var array{repository: string, tag: string, commit: string, licence: string, modified: string, sources: array<string, string>, generated: array<string, string>} */
        return self::decode('provenance.json');
    }

    /**
     * The JSON file at the path, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function decode(string $path): array
    {
        $decoded = json_decode((string) file_get_contents(OcsfValidator::ROOT . '/' . $path), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * Whether the value holds the key at any depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $value
     * @param  string  $key
     * @return bool
     */
    private static function hasKey(array $value, string $key): bool
    {
        foreach ($value as $name => $member) {
            if ($name === $key || (is_array($member) && self::hasKey($member, $key))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every file of the pinned schema, by name, in order.
     *
     * @return list<string>
     */
    private static function files(): array
    {
        $files = array_map(basename(...), array_filter(glob(OcsfValidator::ROOT . '/*') ?: [], is_file(...)));

        sort($files);

        return $files;
    }
}
