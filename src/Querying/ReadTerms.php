<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;

/**
 * The terms a read of the trail ran under, as its record names them: its
 * filters, the scope the policy answered, or `null` when none was, the keyed
 * fingerprint of each, and the id of the ring key that keyed them.
 *
 * A fingerprint is the lower-case hex HMAC-SHA256 of the canonical encoding of
 * the normalised filters, or of the scope, each under a label of its own, with
 * a key derived by HKDF-SHA256 from the secret of the ring key, with an empty
 * salt and an info string of its own, so it is never the key that signs rows,
 * seals or cursors. Filters and scopes are made of morph types and ids, which
 * are few and often sequential, so a digest anyone could compute would give
 * them back to whoever tried candidates until one matched; without the key, a
 * reader of the record learns of them only whether two reads under the same key
 * ran under the same terms. The derived key is made when the terms are and
 * never kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadTerms
{
    /** @var string HKDF info of every fingerprint key. */
    public const string DERIVATION_INFO = 'sinemacula/audit-log:fingerprint:v1';

    /** @var int Length of every fingerprint key, in bytes. */
    private const int KEY_BYTES = 32;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  string  $queryFingerprint
     * @param  ?string  $scopeFingerprint
     * @param  string  $keyId
     */
    private function __construct(

        /** The read's filters. */
        public TrailFilters $filters,

        /** The scope the policy answered, or `null` when none was. */
        public ?AccessScope $scope,

        /** The keyed fingerprint of the normalised filters, as 64 lower-case hex. */
        public string $queryFingerprint,

        /** The keyed fingerprint of the scope, as 64 lower-case hex, or `null` with no scope. */
        public ?string $scopeFingerprint,

        /** The id of the ring key the fingerprints were keyed by. */
        public string $keyId,
    ) {}

    /**
     * The terms of a read under the filters and the scope, fingerprinted under
     * the ring key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\IntegrityKey  $key
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function of(#[\SensitiveParameter] IntegrityKey $key, TrailFilters $filters, ?AccessScope $scope): self
    {
        $fingerprintKey = hash_hkdf('sha256', $key->secret(), self::KEY_BYTES, self::DERIVATION_INFO, '');

        return new self(
            $filters,
            $scope,
            self::fingerprint($fingerprintKey, 'filters', $filters->normalised()),
            $scope === null ? null : self::fingerprint($fingerprintKey, 'scope', $scope->toArray()),
            $key->id,
        );
    }

    /**
     * The keyed fingerprint of the value under the label, as 64 lower-case hex.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $fingerprintKey
     * @param  'filters'|'scope'  $label
     * @param  array<string, mixed>  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function fingerprint(#[\SensitiveParameter] string $fingerprintKey, string $label, array $value): string
    {
        return hash_hmac('sha256', CanonicalEncoder::encode([$label => $value]), $fingerprintKey);
    }
}
