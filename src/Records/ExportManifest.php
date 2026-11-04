<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The manifest of an export of the trail, as the canonical form of an `export`
 * artifact: the format, the viewer, the fingerprints of the scope and the
 * filters, the snapshot the entries were read in, the number of lines, the
 * first and last positions exported, and the digests of the file and of its
 * membership. An export of no line is valid, with no first or last position.
 *
 * The canonical form is the canonical encoding of a map of exactly the keys of
 * its version, `export_manifest_version` among them, so the same export always
 * gives the same bytes and the same digest. A first or last position is the
 * entry's recorded instant and its id, and both are `null` exactly when there
 * are no lines. Reading dispatches on the version a plaintext names, which this
 * release must read, holds it to exactly that version's keys and kinds, and
 * requires its bytes to be the canonical encoding of what they hold. Reading
 * never throws for a malformed plaintext and reads no catalogue, setting or
 * container: a manifest from an earlier release parses by its own version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExportManifest
{
    /** @var int The version of the manifest an export is described in. */
    public const int VERSION = 1;

    /** @var list<int> The versions of the manifest this release reads. */
    public const array SUPPORTED_VERSIONS = [1];

    /** @var list<string> The keys of a version 1 manifest, sorted: exactly these and nothing else. */
    public const array KEYS = [
        'export_manifest_version',
        'file_sha256',
        'first',
        'format',
        'last',
        'lines',
        'membership_sha256',
        'query_fingerprint',
        'scope_fingerprint',
        'snapshot',
        'viewer',
    ];

    /** @var string The key a manifest names its version under. */
    private const string VERSION_KEY = 'export_manifest_version';

    /** @var list<string> The formats an export is written in. */
    private const array FORMATS = ['ndjson', 'ocsf', 'cef'];

    /** @var list<string> The keys of a manifest that are each a lower-case hex SHA-256. */
    private const array DIGESTS = ['file_sha256', 'membership_sha256', 'query_fingerprint', 'scope_fingerprint'];

    /** @var list<string> The keys of the snapshot an export was read in, sorted: exactly these, each a non-empty string. */
    private const array SNAPSHOT_KEYS = ['connection', 'consistency', 'database', 'engine', 'table'];

    /** @var list<string> The keys of the viewer an export was made for, sorted: a reference's. */
    private const array VIEWER_KEYS = ['id', 'type'];

    /** @var int How deep a plaintext is decoded: the manifest, its snapshot, viewer and positions, and their values. */
    private const int DEPTH = 3;

    /** @var string An entry's id as every engine returns it: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string SHA-256 as 64 lower-case hexadecimal characters. */
    private const string DIGEST_PATTERN = '/\A[0-9a-f]{64}\z/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The canonical manifest of an export, each value held to its kind: a
     * format the package writes, 64 lower-case hex digests, a snapshot of
     * exactly its five non-empty names, a count of lines from 0, and a first
     * and last position, each a recorded instant and a lower-case UUID, both
     * `null` exactly when there are no lines.
     *
     * Its parameters are the manifest's fields, each from its own stage of the
     * export, so none groups naturally with another.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $format
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  string  $scopeFingerprint
     * @param  string  $queryFingerprint
     * @param  array{connection: string, consistency: string, database: string, engine: string, table: string}  $snapshot
     * @param  int  $lines
     * @param  ?array{0: string, 1: string}  $first
     * @param  ?array{0: string, 1: string}  $last
     * @param  string  $fileSha256
     * @param  string  $membershipSha256
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public static function canonical(
        string $format,
        #[\SensitiveParameter]
        Reference $viewer,
        string $scopeFingerprint,
        string $queryFingerprint,
        array $snapshot,
        int $lines,
        ?array $first,
        ?array $last,
        string $fileSha256,
        string $membershipSha256,
    ): string {
        $fields = [
            self::VERSION_KEY   => self::VERSION,
            'file_sha256'       => $fileSha256,
            'first'             => $first,
            'format'            => $format,
            'last'              => $last,
            'lines'             => $lines,
            'membership_sha256' => $membershipSha256,
            'query_fingerprint' => $queryFingerprint,
            'scope_fingerprint' => $scopeFingerprint,
            'snapshot'          => $snapshot,
            'viewer'            => ['id' => $viewer->id, 'type' => $viewer->type],
        ];

        $failure = self::failureOf($fields);

        if ($failure !== null) {
            throw new \InvalidArgumentException($failure);
        }

        return CanonicalEncoder::encode($fields);
    }

    /**
     * The manifest of an export as an `export` artifact: its canonical form,
     * counted by its lines.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $format
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  string  $scopeFingerprint
     * @param  string  $queryFingerprint
     * @param  array{connection: string, consistency: string, database: string, engine: string, table: string}  $snapshot
     * @param  int  $lines
     * @param  ?array{0: string, 1: string}  $first
     * @param  ?array{0: string, 1: string}  $last
     * @param  string  $fileSha256
     * @param  string  $membershipSha256
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public static function manifestOf(
        string $format,
        #[\SensitiveParameter]
        Reference $viewer,
        string $scopeFingerprint,
        string $queryFingerprint,
        array $snapshot,
        int $lines,
        ?array $first,
        ?array $last,
        string $fileSha256,
        string $membershipSha256,
    ): Manifest {
        $canonical = self::canonical($format, $viewer, $scopeFingerprint, $queryFingerprint, $snapshot, $lines, $first, $last, $fileSha256, $membershipSha256);

        return Manifest::ofContent(ArtifactKind::EXPORT, $canonical, $lines);
    }

    /**
     * The count, digest and fields of a plaintext that is exactly an export's
     * canonical manifest, in a version this release reads, or `null` for any
     * other plaintext. The count is its lines.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $plaintext
     * @return ?array{count: int, digest: string, fields: array<array-key, mixed>}
     */
    public static function read(#[\SensitiveParameter] string $plaintext): ?array
    {
        $decoded = self::decoded($plaintext);

        if (!is_array($decoded) || !in_array($decoded[self::VERSION_KEY] ?? null, self::SUPPORTED_VERSIONS, true) || self::failureOf($decoded) !== null) {
            return null;
        }

        try {
            $canonical = CanonicalEncoder::encode($decoded);
        } catch (\UnexpectedValueException) {
            // A value with no canonical form is no manifest
            return null;
        }

        return $canonical === $plaintext && is_int($decoded['lines']) ? ['count' => $decoded['lines'], 'digest' => hash('sha256', $plaintext), 'fields' => $decoded] : null;
    }

    /**
     * Why the fields are not a version 1 manifest, or `null` when they are:
     * exactly its keys, then each value of its kind.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return ?string
     */
    private static function failureOf(#[\SensitiveParameter] array $fields): ?string
    {
        if (!self::hasExactly($fields, self::KEYS) || $fields[self::VERSION_KEY] !== self::VERSION) {
            return 'An export manifest holds exactly the keys of its version.';
        }

        return self::scalarsFailure($fields)
            ?? self::positionsFailure($fields['lines'], $fields['first'], $fields['last'])
            ?? self::snapshotFailure($fields['snapshot'])
            ?? self::viewerFailure($fields['viewer']);
    }

    /**
     * Why the format, the line count or a digest is not of its kind, or `null`
     * when each is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return ?string
     */
    private static function scalarsFailure(#[\SensitiveParameter] array $fields): ?string
    {
        if (!in_array($fields['format'], self::FORMATS, true)) {
            return 'An export manifest\'s `format` must be `ndjson`, `ocsf` or `cef`.';
        }

        if (!is_int($fields['lines']) || $fields['lines'] < 0) {
            return 'An export manifest\'s `lines` must be an integer of at least 0.';
        }

        return self::digestsFailure($fields);
    }

    /**
     * Why a digest is not 64 lower-case hex, naming the first, or `null` when
     * each is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return ?string
     */
    private static function digestsFailure(#[\SensitiveParameter] array $fields): ?string
    {
        foreach (self::DIGESTS as $digest) {
            if (!is_string($fields[$digest]) || preg_match(self::DIGEST_PATTERN, $fields[$digest]) !== 1) {
                return sprintf('An export manifest\'s `%s` must be 64 lower-case hexadecimal characters.', $digest);
            }
        }

        return null;
    }

    /**
     * Why the first or the last position is not of its kind, or `null` when
     * both are: `null` exactly when there are no lines, and otherwise a
     * recorded instant and a lower-case UUID.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $lines
     * @param  mixed  $first
     * @param  mixed  $last
     * @return ?string
     */
    private static function positionsFailure(mixed $lines, mixed $first, mixed $last): ?string
    {
        foreach (['first' => $first, 'last' => $last] as $field => $position) {
            if ($lines === 0 ? $position !== null : !self::isPosition($position)) {
                return sprintf('An export manifest\'s `%s` must be a recorded instant and a lower-case UUID, or `null` exactly when there are no lines.', $field);
            }
        }

        return null;
    }

    /**
     * Why the snapshot is not of its kind, or `null` when it is exactly its
     * five names, each a non-empty string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $snapshot
     * @return ?string
     */
    private static function snapshotFailure(mixed $snapshot): ?string
    {
        $message = 'An export manifest\'s `snapshot` must be exactly a non-empty `connection`, `consistency`, `database`, `engine` and `table`.';

        if (!is_array($snapshot) || !self::hasExactly($snapshot, self::SNAPSHOT_KEYS)) {
            return $message;
        }

        foreach ($snapshot as $name) {
            if (!is_string($name) || $name === '') {
                return $message;
            }
        }

        return null;
    }

    /**
     * Why the viewer is not of its kind, or `null` when it is exactly a
     * reference's id and type.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $viewer
     * @return ?string
     */
    private static function viewerFailure(#[\SensitiveParameter] mixed $viewer): ?string
    {
        $message = 'An export manifest\'s `viewer` must be exactly a reference\'s `id` and `type`.';

        if (!is_array($viewer) || !self::hasExactly($viewer, self::VIEWER_KEYS) || !is_string($viewer['type']) || !is_string($viewer['id'])) {
            return $message;
        }

        try {
            Reference::of($viewer['type'], $viewer['id']);
        } catch (\InvalidArgumentException) {
            return $message;
        }

        return null;
    }

    /**
     * Whether the value is a position: a list of exactly a recorded instant and
     * a lower-case UUID.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $position
     * @return bool
     */
    private static function isPosition(mixed $position): bool
    {
        if (!is_array($position) || array_keys($position) !== [0, 1] || !is_string($position[0]) || !is_string($position[1])) {
            return false;
        }

        return StoredTime::isInstant($position[0]) && preg_match(self::UUID_PATTERN, $position[1]) === 1;
    }

    /**
     * Whether the map has exactly the keys given, in any order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $map
     * @param  list<string>  $keys
     * @return bool
     */
    private static function hasExactly(#[\SensitiveParameter] array $map, array $keys): bool
    {
        $given = array_keys($map);

        sort($given);

        return $given === $keys;
    }

    /**
     * The plaintext decoded with objects as arrays, or `null` when it is not
     * JSON or nests deeper than a manifest.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $plaintext
     * @return mixed
     */
    private static function decoded(#[\SensitiveParameter] string $plaintext): mixed
    {
        try {
            return json_decode($plaintext, true, self::DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }
}
