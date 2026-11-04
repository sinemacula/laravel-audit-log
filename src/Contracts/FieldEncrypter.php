<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Field encrypter contract: the seam that seals a value under the key of the
 * person or thing that owns it, for the fields a definition encrypts, the notes
 * that have an owner and the addresses the `encrypt` IP mode stores.
 *
 * The package binds `Privacy\SubjectKeyEncrypter`, which seals each value under
 * a key of its owner's, kept in the package's key store, so an owner's values
 * can be erased by destroying the owner's keys. An application that never wants
 * a value encrypted binds `Privacy\NoFieldEncrypter`, which holds no key for
 * anyone, so every encrypted value is dropped and diagnosed, and never stored
 * in plaintext.
 *
 * The package resolves a fresh encrypter for each record, so an implementation
 * keeps nothing across records. Within one, it may keep the keys of one entry,
 * the `FieldContext::$entryId` it was last given, so the owners list lets it
 * fetch every key the record needs at once, and it must drop them when it is
 * given another entry. It should mark its own plaintext parameter
 * `#[\SensitiveParameter]`, since an attribute on this contract does not reach
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FieldEncrypter
{
    /**
     * The plaintext sealed under the owner's key, as an envelope of exactly
     * three parts: `v`, the envelope's version, from 1; `k`, the id of the key,
     * never the key itself; and `c`, the ciphertext. Both strings must be
     * non-empty clean text, as they are stored and signed as given. `null`
     * means the owner has no key and is given none, whether it never had one or
     * its keys were erased.
     *
     * The plaintext is typed: the canonical JSON of the value, so the string
     * `"true"` and the boolean `true` are sealed apart, and a string arrives
     * with its quotes. It is at most 1024 bytes. The context names the entry
     * the value belongs to, its path within the entry and the log the entry is
     * signed into, which the envelope must be bound to so it opens nowhere
     * else, and the record's tenant, category and every owner it encrypts for,
     * so an implementation can fetch every key the record needs at once.
     *
     * Anything else returned is a failure, and so is anything thrown. The value
     * is dropped and diagnosed, the failure is reported naming only this class,
     * and a thrown exception is discarded and never reported, because its
     * message could hold the plaintext. After a failure the package asks for no
     * more envelopes for that record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return ?array{v: int, k: string, c: string}
     *
     * @throws \Throwable
     */
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): ?array;
}
