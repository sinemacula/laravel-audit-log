<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;

/**
 * The terms a read ran under, with keyed fingerprints of its filters and scope.
 *
 * They are keyed because morph types and ids are few and often sequential, so a
 * plain digest would give them back to anyone trying candidates.
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

        /** The keyed fingerprint of the normalised filters. */
        public string $queryFingerprint,

        /** The keyed fingerprint of the scope, or `null` with no scope. */
        public ?string $scopeFingerprint,

        /** The id of the ring key the fingerprints were keyed by. */
        public string $keyId,
    ) {}

    /**
     * The terms of a read, fingerprinted under a key derived from the ring key.
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
     * The hex HMAC of the value under the label.
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
