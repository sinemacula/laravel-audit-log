<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;

/**
 * What the journal's believed `rewrap` rows commit each key to: the state, the
 * wrapping key id and the wrapped key's digest its latest listing left it in,
 * by key id, folded in sequence order so a later listing replaces an earlier
 * one.
 *
 * A key's state, wrapping key id and wrapped key are its mutable columns, left
 * out of its signature: the wrap context binds the wrapped key to its row, and
 * the journal binds the state. Only a rewrap supersedes a key or replaces its
 * wrapped key, so a key that holds a key must be as its latest listing left it,
 * and a key no rewrap lists must be live: a superseded key no rewrap
 * superseded, a live key whose latest listing superseded it, and a key whose
 * wrapping differs from its latest listing are each `key_substituted`, as a
 * restore or a hand edit of those columns leaves them.
 *
 * Each commitment is kept as one digest of the three values, so a key costs its
 * id and 32 bytes however its listing was written.
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
     * Fold a believed journal row in: a `rewrap` row's listed keys replace
     * whatever an earlier listing committed them to; any other row, a payload
     * that cannot be read, and a listing that is not well formed commit
     * nothing.
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
     * The finding the key row's state and wrapping give against its latest
     * listing, or `null` when they agree: a key no rewrap lists must be live,
     * and one a rewrap lists must hold the state, wrapping key and wrapped key
     * its latest listing left it with. A key that holds no key is the erasure
     * check's, and gives none here.
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
     * `null` when the listing is not a map of a string `key_id` and an `after`
     * of a string state, wrapping key id and wrapped digest.
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
