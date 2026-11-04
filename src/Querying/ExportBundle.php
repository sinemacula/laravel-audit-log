<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;

/**
 * The offline bundle published beside an export as `<file>.manifest.json`: the
 * canonical encoding of exactly four keys, `bundle_version`, the descriptor of
 * the export's artifact, the signed columns of the entry that journalled the
 * export, and the export's canonical manifest as a string, followed by one line
 * feed.
 *
 * With the bundle alone an auditor checks the file's digest and its membership
 * digest against the manifest, the manifest's digest against the descriptor the
 * entry signs, and, holding the key, the entry's HMAC over its columns. Nothing
 * in it is trusted: the bundle is what verification checks, never what it
 * believes.
 *
 * Decoding accepts exactly what encoding writes and nothing else: the four
 * keys, version 1, a descriptor of exactly its four keys, each of its kind, an
 * entry that is an object, a manifest that is a string, and bytes that are
 * exactly their canonical encoding and one line feed, within the envelope's
 * bound. It never throws for malformed contents. The entry keeps its JSON
 * columns as they were decoded, objects as objects, so it encodes to the bytes
 * it was signed over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExportBundle
{
    /** @var int The version of the bundle an export is published with. */
    public const int VERSION = 1;

    /** @var list<string> A bundle's keys, exactly, sorted as the canonical encoding writes them. */
    private const array KEYS = ['bundle_version', 'descriptor', 'entry', 'manifest'];

    /** @var array<string, 'integer'|'string'> A descriptor's keys, exactly, sorted, each with the kind of its value. */
    private const array DESCRIPTOR = [
        'artifact_id' => 'string',
        'count'       => 'integer',
        'digest'      => 'string',
        'kind'        => 'string',
    ];

    /** @var int How deep a bundle is decoded: one more than an envelope, for the bundle's own object. */
    private const int DEPTH = 514;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The bundle of an export: the canonical encoding of its version, the
     * descriptor, the entry's columns and the manifest, and one line feed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @param  array<array-key, mixed>  $entryColumns
     * @param  string  $manifest
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function encode(array $descriptor, #[\SensitiveParameter] array $entryColumns, #[\SensitiveParameter] string $manifest): string
    {
        if (!self::isDescriptor($descriptor)) {
            throw new \InvalidArgumentException('An export bundle\'s descriptor holds exactly a string `artifact_id`, an integer `count`, a string `digest` and a string `kind`.');
        }

        $bundle = CanonicalEncoder::encode([
            'bundle_version' => self::VERSION,
            'descriptor'     => $descriptor,
            'entry'          => (object) $entryColumns,
            'manifest'       => $manifest,
        ]) . "\n";

        if (strlen($bundle) > EnvelopeCodec::MAX_BYTES) {
            throw new \InvalidArgumentException(sprintf('An export bundle must be at most %d bytes.', EnvelopeCodec::MAX_BYTES));
        }

        return $bundle;
    }

    /**
     * The descriptor, the entry's columns and the manifest a bundle holds, or
     * `null` for contents that are not exactly a bundle this release writes.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $contents
     * @return ?array{descriptor: array{artifact_id: string, count: int, digest: string, kind: string}, entry: array<array-key, mixed>, manifest: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function decode(#[\SensitiveParameter] string $contents): ?array
    {
        $bundle = self::fieldsOf($contents);

        if ($bundle === null || !self::hasExactly($bundle, self::KEYS) || $bundle['bundle_version'] !== self::VERSION) {
            return null;
        }

        $descriptor = $bundle['descriptor'] instanceof \stdClass ? get_object_vars($bundle['descriptor']) : null;

        if ($descriptor === null || !self::isDescriptor($descriptor) || !$bundle['entry'] instanceof \stdClass || !is_string($bundle['manifest'])) {
            return null;
        }

        return ['descriptor' => $descriptor, 'entry' => get_object_vars($bundle['entry']), 'manifest' => $bundle['manifest']];
    }

    /**
     * The fields of contents that are within the bound and are exactly the
     * canonical encoding of a JSON object and one line feed, or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $contents
     * @return ?array<array-key, mixed>
     */
    private static function fieldsOf(#[\SensitiveParameter] string $contents): ?array
    {
        if (strlen($contents) > EnvelopeCodec::MAX_BYTES || !str_ends_with($contents, "\n")) {
            return null;
        }

        $json = substr($contents, 0, -1);

        try {
            $decoded = json_decode($json, false, self::DEPTH, JSON_THROW_ON_ERROR);

            return $decoded instanceof \stdClass && CanonicalEncoder::encode($decoded) === $json ? get_object_vars($decoded) : null;
        } catch (\JsonException|\UnexpectedValueException) {
            // Contents that are not JSON, or hold a value with no canonical
            // form, are no bundle
            return null;
        }
    }

    /**
     * Whether the descriptor holds exactly its four keys, each of its kind.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return bool
     *
     * @phpstan-assert-if-true array{artifact_id: string, count: int, digest: string, kind: string} $descriptor
     */
    private static function isDescriptor(array $descriptor): bool
    {
        if (!self::hasExactly($descriptor, array_keys(self::DESCRIPTOR))) {
            return false;
        }

        foreach (self::DESCRIPTOR as $key => $kind) {
            if (gettype($descriptor[$key]) !== $kind) {
                return false;
            }
        }

        return true;
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
        $given = array_map(strval(...), array_keys($map));

        sort($given);

        return $given === $keys;
    }
}
