<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Records\DisclosureManifest;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\Manifest;

/**
 * Classifies a stored artifact against the descriptor its entry signed, so each
 * way an artifact can differ is reported as its own finding: a descriptor that
 * is not exactly an artifact id, a known kind, a digest and a count that kind
 * allows is `manifest_malformed`; no stored artifact is `manifest_missing`; an
 * artifact under another id, or naming another entry, is `manifest_swapped`;
 * one stored as another kind is `manifest_wrong_kind`; one counting other
 * members or holding another digest is `manifest_mismatch`; and members that
 * open to no canonical form of the signed kind are `manifest_malformed`, while
 * a canonical form of that kind other than the one signed is
 * `manifest_tampered`.
 *
 * Each kind's plaintext is read by its own reader: a bulk operation's by the
 * manifest, a disclosure's and an export's by their versioned readers, none of
 * which reads the catalogue, a setting or the container. Nothing here reads the
 * database or decrypts; the manifest verifier does both and asks this what it
 * found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ArtifactInspector
{
    /** @var list<string> The keys of a descriptor, sorted: exactly these and nothing else. */
    private const array DESCRIPTOR_KEYS = ['artifact_id', 'count', 'digest', 'kind'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the value is exactly a descriptor: an artifact id that is a
     * lower-case UUID, a kind the package knows, a digest of 64 lower-case hex
     * and an integer count, at least one for a bulk operation and at least none
     * for any other kind, and no other key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return bool
     *
     * @phpstan-assert-if-true array{artifact_id: string, count: int, digest: string, kind: string} $descriptor
     */
    public static function isDescriptor(array $descriptor): bool
    {
        $keys = array_keys($descriptor);

        sort($keys);

        if ($keys !== self::DESCRIPTOR_KEYS) {
            return false;
        }

        ['artifact_id' => $id, 'kind' => $kind, 'digest' => $digest, 'count' => $count] = $descriptor;

        $known = is_string($kind) ? ArtifactKind::tryFrom($kind) : null;

        if (!is_string($id) || $known === null || !is_string($digest) || !is_int($count)) {
            return false;
        }

        return $count >= ($known->allowsEmpty() ? 0 : 1) && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1 && preg_match(SealEnvelope::DIGEST_PATTERN, $digest) === 1;
    }

    /**
     * The finding of the entry's stored artifact columns, or `null` when they
     * are the ones its descriptor signed, checked in this order: no artifact is
     * missing; another artifact id, or an artifact naming another entry, is
     * swapped; another kind is the wrong kind; and another count or digest is a
     * mismatch.
     *
     * @param  ?array<string, scalar|null>  $stored
     * @param  string  $entryId
     * @param  array{artifact_id: string, count: int, digest: string, kind: string}  $descriptor
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    public static function columnsFinding(#[\SensitiveParameter] ?array $stored, string $entryId, array $descriptor): ?Finding
    {
        return match (true) {
            $stored === null                                                                                       => Finding::MANIFEST_MISSING,
            ($stored['id'] ?? null)   !== $descriptor['artifact_id'] || ($stored['entry_id'] ?? null) !== $entryId => Finding::MANIFEST_SWAPPED,
            ($stored['kind'] ?? null) !== $descriptor['kind']                                                      => Finding::MANIFEST_WRONG_KIND,
            !self::countsAndDigests($stored, $descriptor)                                                          => Finding::MANIFEST_MISMATCH,
            default                                                                                                => null,
        };
    }

    /**
     * The finding of an artifact's decrypted members, or `null` when they are
     * exactly the canonical form the descriptor signed: a plaintext the signed
     * kind's reader does not read as a canonical form of that kind is
     * malformed, and a canonical form of another count or digest is tampered.
     *
     * @param  string  $plaintext
     * @param  array{artifact_id: string, count: int, digest: string, kind: string}  $descriptor
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    public static function plaintextFinding(#[\SensitiveParameter] string $plaintext, array $descriptor): ?Finding
    {
        $read = self::canonicalOf($plaintext, ArtifactKind::from($descriptor['kind']));

        if ($read === null) {
            return Finding::MANIFEST_MALFORMED;
        }

        return $read['count'] === $descriptor['count'] && $read['digest'] === $descriptor['digest'] ? null : Finding::MANIFEST_TAMPERED;
    }

    /**
     * Whether the stored artifact counts the members and holds the digest the
     * descriptor signed.
     *
     * @param  array<string, scalar|null>  $stored
     * @param  array{artifact_id: string, count: int, digest: string, kind: string}  $descriptor
     * @return bool
     */
    private static function countsAndDigests(#[\SensitiveParameter] array $stored, array $descriptor): bool
    {
        return IntegerSetting::parse($stored['member_count'] ?? null) === $descriptor['count'] && ($stored['digest'] ?? null) === $descriptor['digest'];
    }

    /**
     * The count and digest of a plaintext that is exactly a canonical form of
     * the kind, read by that kind's reader, or `null` for any other plaintext.
     *
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @return ?array{count: int, digest: string}
     */
    private static function canonicalOf(#[\SensitiveParameter] string $plaintext, ArtifactKind $kind): ?array
    {
        try {
            $read = match ($kind) {
                ArtifactKind::BULK       => Manifest::readCanonical($plaintext),
                ArtifactKind::DISCLOSURE => DisclosureManifest::read($plaintext),
                ArtifactKind::EXPORT     => ExportManifest::read($plaintext),
            };
        } catch (\JsonException) {
            return null;
        }

        return $read === null ? null : ['count' => $read['count'], 'digest' => $read['digest']];
    }
}
