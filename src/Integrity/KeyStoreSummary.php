<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * What one verification of the owners' key store established: how many key rows
 * it verified, how many of them were erased, and how many key findings it added
 * to the run; or that it was skipped, because the bound field encrypter is not
 * the package's, with that encrypter's class.
 *
 * It names counts and a class, never a key, an owner or a value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyStoreSummary
{
    /**
     * Constructor.
     *
     * @param  int  $keys
     * @param  int  $erased
     * @param  int  $findings
     * @param  bool  $skipped
     * @param  ?string  $encrypter
     */
    public function __construct(

        /** The key rows read and verified. */
        public int $keys = 0,

        /** The key rows among them that were erased or hold no wrapped key. */
        public int $erased = 0,

        /** How many key findings the verification added to the run. */
        public int $findings = 0,

        /** Whether the key store was not verified, the bound field encrypter not being the package's. */
        public bool $skipped = false,

        /** The class of the bound field encrypter the verification was skipped for, or `null` when it ran. */
        public ?string $encrypter = null,
    ) {}

    /**
     * The summary of a verification that was skipped, before it names the
     * encrypter it was skipped for.
     *
     * @return self
     */
    public static function skipped(): self
    {
        return new self(skipped: true);
    }

    /**
     * The summary naming the bound field encrypter, when it was skipped for it;
     * a verification that ran is about no encrypter, and is returned as it is.
     *
     * @param  string  $encrypter
     * @return self
     */
    public function naming(string $encrypter): self
    {
        return $this->skipped ? new self($this->keys, $this->erased, $this->findings, true, $encrypter) : $this;
    }

    /**
     * The summary as the key store's part of the run's summary.
     *
     * @return array{keys: int, erased: int, findings: int, skipped: bool, encrypter: ?string}
     */
    public function toArray(): array
    {
        return [
            'keys'      => $this->keys,
            'erased'    => $this->erased,
            'findings'  => $this->findings,
            'skipped'   => $this->skipped,
            'encrypter' => $this->encrypter,
        ];
    }
}
