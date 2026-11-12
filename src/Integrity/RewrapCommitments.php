<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;

/**
 * Each key's state and wrapping as its latest believed `rewrap` listing left
 * them, which the key's signature does not cover.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RewrapCommitments
{
    /** @var array<string, string> The binary digest of each listed key's latest state, wrapping key id and wrapped digest, by key id. */
    private array $committed = [];

    /**
     * Fold a believed journal row in; only a well-formed `rewrap` listing
     * commits anything, replacing the key's earlier listing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return void
     */
    public function fold(#[\SensitiveParameter] JournalRow $journalRow): void
    {
        if ($journalRow->kind !== JournalKind::REWRAP) {
            return;
        }

        try {
            $keys = ($journalRow->payloadMap() ?? [])['keys'] ?? null;
        } catch (\JsonException) {
            // A payload that cannot be read commits nothing
            return;
        }

        foreach (is_array($keys) ? $keys : [] as $listed) {
            $commitment = self::commitmentOf($listed);

            if ($commitment === null) {
                continue;
            }

            [$id, $digest] = $commitment;

            $this->committed[$id] = $digest;
        }
    }

    /**
     * The finding against the key's latest listing, or `null`. An unlisted key
     * must be live; a key holding none is the erasure check's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    public function findingOf(#[\SensitiveParameter] SubjectKeyRow $keyRow): ?Finding
    {
        if (!$keyRow->state->holdsAKey()) {
            return null;
        }

        $committed = $this->committed[$keyRow->id] ?? null;

        if ($committed === null) {
            return $keyRow->state === KeyState::LIVE ? null : Finding::KEY_SUBSTITUTED;
        }

        $current = self::digestOf($keyRow->state->value, (string) $keyRow->wrapKeyId, (string) $keyRow->wrappedDigest());

        return hash_equals($committed, $current) ? null : Finding::KEY_SUBSTITUTED;
    }

    /**
     * The key id a listing names and the digest of what it left the key in, or
     * `null` when the listing is malformed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $listed
     * @return ?array{0: string, 1: string}
     */
    private static function commitmentOf(#[\SensitiveParameter] mixed $listed): ?array
    {
        $id        = is_array($listed) ? ($listed['key_id'] ?? null) : null;
        $after     = is_array($listed) && is_array($listed['after'] ?? null) ? $listed['after'] : [];
        $state     = $after['state']          ?? null;
        $wrapKeyId = $after['wrap_key_id']    ?? null;
        $digest    = $after['wrapped_digest'] ?? null;

        if (!is_string($id) || !is_string($state) || !is_string($wrapKeyId) || !is_string($digest)) {
            return null;
        }

        return [$id, self::digestOf($state, $wrapKeyId, $digest)];
    }

    /**
     * The binary digest of a key's state, wrapping key id and wrapped key
     * digest, each length-prefixed so no two triples encode alike.
     *
     * @param  string  $state
     * @param  string  $wrapKeyId
     * @param  string  $wrappedDigest
     * @return string
     */
    private static function digestOf(string $state, string $wrapKeyId, string $wrappedDigest): string
    {
        return hash('sha256', pack('N', strlen($state)) . $state . pack('N', strlen($wrapKeyId)) . $wrapKeyId . $wrappedDigest, true);
    }
}
