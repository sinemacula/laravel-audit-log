<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;

/**
 * Thrown when an erasure is refused, writing nothing.
 *
 * Its message names the refusal and its reason count, never the owner, a reason
 * or a fingerprint.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ErasureRefusedException extends \RuntimeException
{
    /** @var string The message, by refusal and reason count. */
    private const string MESSAGE = 'The erasure was refused (`%s`, %d %s); nothing was written.';

    /** @var list<string> The distinct reasons, sorted bytewise. */
    private readonly array $reasons;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal  $refusal
     * @param  list<string>  $reasons
     * @param  string  $fingerprint
     * @param  string  $fingerprintKey
     */
    private function __construct(

        /** Why the erasure was refused. */
        private readonly ErasureRefusal $refusal,

        // Not promoted: deduplicated and sorted into $this->reasons.
        array $reasons,

        /** The owner's fingerprint, under the ring key named. */
        private readonly string $fingerprint,

        /** The id of the ring key the fingerprint was taken under. */
        private readonly string $fingerprintKey,
    ) {
        $unique = array_values(array_unique($reasons));

        sort($unique, SORT_STRING);

        $this->reasons = $unique;

        parent::__construct(sprintf(self::MESSAGE, $refusal->value, count($unique), count($unique) === 1 ? 'reason' : 'reasons'));
    }

    /**
     * The erasure was refused for the reasons given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal  $refusal
     * @param  list<string>  $reasons
     * @param  string  $fingerprint
     * @param  string  $fingerprintKey
     * @return self
     */
    public static function of(ErasureRefusal $refusal, array $reasons, string $fingerprint, string $fingerprintKey): self
    {
        return new self($refusal, $reasons, $fingerprint, $fingerprintKey);
    }

    /**
     * Why the erasure was refused.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal
     */
    public function refusal(): ErasureRefusal
    {
        return $this->refusal;
    }

    /**
     * The distinct reasons, sorted bytewise.
     *
     * @return list<string>
     */
    public function reasons(): array
    {
        return $this->reasons;
    }

    /**
     * The owner's HMAC-SHA256 fingerprint in lower-case hex.
     *
     * @return string
     */
    public function fingerprint(): string
    {
        return $this->fingerprint;
    }

    /**
     * The id of the ring key the owner's fingerprint was taken under.
     *
     * @return string
     */
    public function fingerprintKey(): string
    {
        return $this->fingerprintKey;
    }
}
