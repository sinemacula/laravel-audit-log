<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * It verifies with no class of the package, as an auditor would: the golden
 * export's file and membership digests are checked against its bundle's
 * manifest with nothing but `hash_file()`, `json_decode()` and a loop over the
 * lines; the export entry's HMAC is recomputed over its canonical columns with
 * a key derived from the application key alone; and the manifest is shown to be
 * the very one the signed entry describes, so an edited manifest cannot pass
 * beside an untouched entry.
 *
 * Nothing here loads the package: the canonical encoding and the key derivation
 * are written out as an auditor would write them from the documentation, which
 * is what the test proves possible.
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
     * The file's SHA-256 is the manifest's, and the SHA-256 of each line's id
     * and a line feed, in file order, is its membership digest, over as many
     * lines as it counts, from its first position to its last.
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

        self::assertCount($manifest['lines'], $ids);
        self::assertSame($manifest['membership_sha256'], hash('sha256', implode('', array_map(static fn (string $id): string => $id . "\n", $ids))));
        self::assertSame($manifest['first'], $positions[0]);
        self::assertSame($manifest['last'], $positions[count($positions) - 1]);
    }

    /**
     * The export entry's HMAC is HMAC-SHA256 over the canonical encoding of
     * every column but `hmac`, under the key HKDF derives from the application
     * key, whose id the entry names; and each line verifies the same way.
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
     * The manifest is the one the signed entry describes: its SHA-256 is the
     * digest of the entry's own `properties._audit.manifest`, whose artifact
     * id, kind `export` and count are the bundle's descriptor, and the entry's
     * `file_sha256` and `returned` are the manifest's.
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
     * A manifest edited beside an untouched entry fails offline: its digest is
     * no longer the one the entry signs, and editing the entry's descriptor to
     * match breaks the entry's HMAC.
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
     * The bundle, decoded with its objects as objects, after checking it is one
     * canonical JSON object followed by one line feed.
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
     * The integrity key derived from the application key, and its id: HKDF with
     * SHA-256 to 32 bytes under the integrity info, and `d` followed by the
     * first 16 hexadecimal characters of the HMAC of `audit-log:key-id` under
     * it.
     *
     * @return array{0: string, 1: string}
     */
    private static function key(): array
    {
        $secret = hash_hkdf('sha256', self::APPLICATION_KEY, 32, self::DERIVATION_INFO, '');

        return [$secret, 'd' . substr(hash_hmac('sha256', 'audit-log:key-id', $secret), 0, 16)];
    }

    /**
     * The HMAC-SHA256 of the row's columns but `hmac`, canonically encoded,
     * under the secret.
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
     * The canonical encoding, as the documentation states it: `null`, booleans
     * and integers as JSON writes them, strings through `json_encode()` with
     * fixed flags, a list as its members in order, and an object as its members
     * with their keys sorted bytewise.
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
