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
 * The package's field encrypter: it seals each value under a key of its
 * owner's, kept in the package's key store, so an owner's values can be erased
 * by destroying the owner's keys.
 *
 * A key belongs to a unit, the owner with the record's tenant and category. On
 * the first value of an entry every unit the record encrypts for is looked up
 * at once, in one statement on the storage connection's writer, and each live
 * key found, its signature verified, is unwrapped. A unit with no live key is
 * given one when a value first needs it, on the key store's own session, so it
 * survives a host transaction that rolls back; an owner whose latest marker
 * records an erasure is given none, and its values are dropped, as any value of
 * an owner with no key is. Each value is then sealed with AES-256-GCM under a
 * field key derived from the unit's data key and the entry id, bound to the
 * entry, its path and the log.
 *
 * No key outlives one operation in memory: the data keys this encrypter holds
 * are those of one entry, and a value of another entry starts afresh, looking
 * every key up again, so an erasure committed between two records is seen by
 * the second. It holds no wrapping key's secret, which the wrapper reads anew
 * on every call. It is built for one record's minimisation and is never bound
 * as a singleton. A failure of the key store or the wrapper is thrown, and the
 * sealer contains it, naming only this class.
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

    /** @var array<string, ?array{0: string, 1: string}> Each unit's key id and data key for the entry, by the unit's digest, `null` for a unit given no key. */
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
     * The plaintext sealed under the key of the owner's unit for the context,
     * as an envelope naming the key, or `null` when the owner is given no key
     * because its latest marker records an erasure.
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
     * Look up, once per entry, the live key of every unit the record encrypts
     * for, in one statement, and unwrap each one found; the keys of any earlier
     * entry are let go first.
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
     * The unit's key id and data key for the entry: the one looked up, or one
     * created now and kept for the entry's other values, or `null` when the
     * unit is given none.
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
     * The data key the live row wraps, unwrapped under its own wrap context.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $row
     * @return string
     *
     * @throws \Throwable
     */
    private function unwrapped(#[\SensitiveParameter] SubjectKeyRow $row): string
    {
        // A live row holds its wrapped key and its wrapping key's id, as its
        // state requires
        return $this->wrapper->unwrap((string) $row->wrappedKey, (string) $row->wrapKeyId, $row->wrapContext());
    }
}
