<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyCreator;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Seals each value under its owner's key in the package's key store; keys are
 * held for one entry, so the next sees an erasure that landed in between.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SubjectKeyEncrypter implements FieldEncrypter
{
    /** @var ?string The entry whose keys are held, or `null` before the first value. */
    private ?string $entryId = null;

    /** @var array<string, ?array{0: string, 1: string}> Each unit's key id and data key for the entry, by unit digest, `null` for a unit given no key. */
    private array $keys = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyStore  $store
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyCreator  $creator
     * @param  \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     */
    public function __construct(

        /** Reads the live keys of the record's units. */
        private readonly KeyStore $store,

        /** Creates a unit's key when a value first needs one. */
        private readonly KeyCreator $creator,

        /** Unwraps each live key found. */
        private readonly KeyWrapper $wrapper,
    ) {}

    /**
     * The plaintext sealed under the owner's unit key, or `null` when the owner
     * is erased and given no key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return ?array{v: int, k: string, c: string}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    #[\Override]
    public function encrypt(#[\SensitiveParameter] Reference $owner, #[\SensitiveParameter] string $plaintext, #[\SensitiveParameter] FieldContext $context): ?array
    {
        $this->lookUp($context);

        $key = $this->keyOf(new KeyUnit($owner, $context->tenant, $context->category));

        if ($key === null) {
            return null;
        }

        [$keyId, $dataKey] = $key;

        return FieldCipher::seal($dataKey, $keyId, $plaintext, $context->entryId, $context->path, $context->logId);
    }

    /**
     * Look up and unwrap every unit's live key once per entry, letting go of
     * any earlier entry's keys first.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    private function lookUp(#[\SensitiveParameter] FieldContext $context): void
    {
        if ($this->entryId === $context->entryId) {
            return;
        }

        $this->entryId = null;
        $this->keys    = [];

        $units = array_map(static fn (#[\SensitiveParameter] Reference $owner): KeyUnit => new KeyUnit($owner, $context->tenant, $context->category), $context->owners);
        $keys  = [];

        foreach ($this->store->liveFor($units) as $digest => $row) {
            $keys[$digest] = [$row->id, $this->unwrapped($row)];
        }

        $this->keys    = $keys;
        $this->entryId = $context->entryId;
    }

    /**
     * The unit's key id and data key: the one looked up, one created now, or
     * `null` when the unit is given none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return ?array{0: string, 1: string}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    private function keyOf(#[\SensitiveParameter] KeyUnit $unit): ?array
    {
        $digest = $unit->digest();

        if (array_key_exists($digest, $this->keys)) {
            return $this->keys[$digest];
        }

        $made = $this->creator->create($unit);

        return $this->keys[$digest] = $made === null ? null : [$made[0]->id, $made[1]];
    }

    /**
     * The data key the live row wraps.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $row
     * @return string
     *
     * @throws \Throwable
     */
    private function unwrapped(#[\SensitiveParameter] SubjectKeyRow $row): string
    {
        // A live row always holds its wrapped key and wrapping key id
        return $this->wrapper->unwrap((string) $row->wrappedKey, (string) $row->wrapKeyId, $row->wrapContext());
    }
}
