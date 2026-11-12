<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Proves an auditor can verify the golden export with no class of the package,
 * from the documented encoding and key derivation alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class OfflineVerificationTest extends TestCase
{
    /** @var string The golden export's file. */
    private const string FILE = __DIR__ . '/../../Fixtures/Export/golden-v1/export.ndjson';

    /** @var string The golden export's bundle. */
    private const string BUNDLE = self::FILE . '.manifest.json';

    /** @var string The application key the golden export was signed under, as its raw 32 bytes. */
    private const string APPLICATION_KEY = 'laravel-audit-log test key!!!!!!';

    /** @var string The HKDF info every integrity key is derived under. */
    private const string DERIVATION_INFO = 'sinemacula/audit-log:integrity:v1';

    /** @var int The flags every string is encoded with in the canonical encoding. */
    private const int JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

    /**
     * The file and membership digests verify against the manifest alone.
     *
     * @return void
     */
    public function testTheFileAndMembershipDigestsVerifyWithoutThePackage(): void
    {
        $manifest = self::manifest();

        self::assertSame($manifest['file_sha256'], hash_file('sha256', self::FILE));

        $ids       = [];
        $positions = [];

        foreach (file(self::FILE, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $entry = json_decode($line, true, 513, JSON_THROW_ON_ERROR);

            self::assertIsArray($entry);
            self::assertIsString($entry['id']);

            $ids[]       = $entry['id'];
            $positions[] = [$entry['recorded_at'], $entry['id']];
        }

        self::assertIsInt($manifest['lines']);
        self::assertCount($manifest['lines'], $ids);
        self::assertSame($manifest['membership_sha256'], hash('sha256', implode('', array_map(static fn (string $id): string => $id . "\n", $ids))));
        self::assertSame($manifest['first'], $positions[0]);
        self::assertSame($manifest['last'], $positions[count($positions) - 1]);
    }

    /**
     * The entry's HMAC verifies under a key derived from the app key alone.
     *
     * @return void
     */
    public function testTheEntryHmacVerifiesWithTheKeyAlone(): void
    {
        [$secret, $keyId] = self::key();

        $entry = self::bundle()->entry;

        self::assertInstanceOf(\stdClass::class, $entry);
        self::assertSame($keyId, $entry->key_id);
        self::assertSame(self::hmacOf($entry, $secret), $entry->hmac);

        foreach (file(self::FILE, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $row = json_decode($line, false, 513, JSON_THROW_ON_ERROR);

            self::assertInstanceOf(\stdClass::class, $row);
            self::assertSame(self::hmacOf($row, $secret), $row->hmac);
        }
    }

    /**
     * The manifest is the one the signed entry describes.
     *
     * @return void
     */
    public function testTheManifestIsTheOneTheSignedEntryDescribes(): void
    {
        $bundle     = self::bundle();
        $properties = $bundle->entry->properties;
        $signed     = $properties->_audit->manifest;
        $manifest   = self::manifest();

        self::assertSame(hash('sha256', $bundle->manifest), $signed->digest);
        self::assertSame('export', $signed->kind);
        self::assertSame([$bundle->descriptor->artifact_id, $bundle->descriptor->kind, $bundle->descriptor->count], [$signed->artifact_id, $signed->kind, $signed->count]);
        self::assertSame($bundle->descriptor->digest, $signed->digest);
        self::assertSame($manifest['file_sha256'], $properties->file_sha256);
        self::assertSame($manifest['lines'], $properties->returned);
        self::assertSame($manifest['lines'], $signed->count);
        self::assertSame('audit_log.trail_exported', $bundle->entry->event);
    }

    /**
     * An edited manifest fails offline, and matching the entry breaks its HMAC.
     *
     * @return void
     */
    public function testAnEditedManifestFailsOffline(): void
    {
        [$secret] = self::key();

        $bundle = self::bundle();
        $edited = str_replace('"lines":3', '"lines":2', $bundle->manifest);

        self::assertNotSame($bundle->manifest, $edited);
        self::assertNotSame(hash('sha256', $edited), $bundle->entry->properties->_audit->manifest->digest);

        $forged = json_decode(json_encode($bundle->entry, self::JSON_FLAGS), false, 512, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $forged);

        $forged->properties->_audit->manifest->digest = hash('sha256', $edited);

        self::assertNotSame(self::hmacOf($forged, $secret), $forged->hmac);
    }

    /**
     * The bundle, decoded with objects, once checked as canonical JSON.
     *
     * @return \stdClass
     */
    private static function bundle(): \stdClass
    {
        $contents = (string) file_get_contents(self::BUNDLE);

        self::assertStringEndsWith("\n", $contents);

        $bundle = json_decode(substr($contents, 0, -1), false, 514, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $bundle);
        self::assertSame(substr($contents, 0, -1), self::canonical($bundle));
        self::assertSame(1, $bundle->bundle_version);

        return $bundle;
    }

    /**
     * The bundle's manifest, decoded with its maps as arrays.
     *
     * @return array<string, array<string, string>|int|list<string>|string|null>
     */
    private static function manifest(): array
    {
        $manifest = json_decode(self::bundle()->manifest, true, 3, JSON_THROW_ON_ERROR);

        self::assertIsArray($manifest);
        self::assertSame(1, $manifest['export_manifest_version']);

        /** @var array<string, array<string, string>|int|list<string>|string|null> */
        return $manifest;
    }

    /**
     * The integrity key derived from the application key, and its id.
     *
     * @return array{0: string, 1: string}
     */
    private static function key(): array
    {
        $secret = hash_hkdf('sha256', self::APPLICATION_KEY, 32, self::DERIVATION_INFO, '');

        return [$secret, 'd' . substr(hash_hmac('sha256', 'audit-log:key-id', $secret), 0, 16)];
    }

    /**
     * The HMAC-SHA256 of the row's canonical columns but `hmac`.
     *
     * @param  \stdClass  $row
     * @param  string  $secret
     * @return string
     */
    private static function hmacOf(\stdClass $row, #[\SensitiveParameter] string $secret): string
    {
        $columns = get_object_vars($row);

        unset($columns['hmac']);

        return hash_hmac('sha256', self::canonical((object) $columns), $secret);
    }

    /**
     * The canonical encoding, written out from the documentation.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     */
    private static function canonical(mixed $value): string
    {
        if (is_array($value)) {
            return '[' . implode(',', array_map(self::canonical(...), $value)) . ']';
        }

        if (!$value instanceof \stdClass) {
            return json_encode($value, self::JSON_FLAGS);
        }

        $members = get_object_vars($value);

        ksort($members, SORT_STRING);

        $keys    = array_map(strval(...), array_keys($members));
        $encoded = array_map(static fn (string $key): string => json_encode($key, self::JSON_FLAGS) . ':' . self::canonical($members[$key]), $keys);

        return '{' . implode(',', $encoded) . '}';
    }
}
