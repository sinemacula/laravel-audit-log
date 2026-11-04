<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;

/**
 * Thrown when an erasure is refused, writing nothing: a key of the owner is
 * blocked and the erasure was not asked to go ahead in part; the outbox holds
 * records older than the erasure and it was not asked to accept them; the bound
 * field encrypter keeps its keys where the package cannot see them; a key of
 * the owner does not authenticate; or the owner holds more keys than one
 * erasure destroys.
 *
 * It carries the refusal, its reasons, sorted bytewise (each blocked key's
 * `held:<hold id>`, `preserved:<category>` and `unverified` once, the ids of
 * the keys that do not authenticate, or the bound encrypter's class), and the
 * owner's keyed fingerprint with the id of the ring key it was taken under, for
 * the refusal's record. Its message names the refusal and how many reasons it
 * has, never the owner, a reason or a fingerprint; the package never gives it
 * another exception.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ErasureRefusedException extends \RuntimeException
{
    /** @var string What every refusal says, by the refusal and how many reasons it has. */
    private const string MESSAGE = 'The erasure was refused (`%s`, %d %s); nothing was written.';

    /** @var list<string> The refusal's reasons, each once, sorted bytewise. */
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

        // The refusal's reasons, in any order and with repeats.
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
     * The erasure was refused for the reasons given, about the owner whose
     * fingerprint, under the ring key named, is given.
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
     * The refusal's reasons, each once, sorted bytewise.
     *
     * @return list<string>
     */
    public function reasons(): array
    {
        return $this->reasons;
    }

    /**
     * The owner's fingerprint: HMAC-SHA256, lower-case hex, under the ring key
     * `fingerprintKey()` names.
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
