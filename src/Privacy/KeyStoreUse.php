<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;

/**
 * Whether the package's key store is the one in use: erasure, the trail filter
 * for an owner's entries and the key store's part of verification all rely on
 * it, and on nothing a custom encrypter keeps.
 *
 * It is in use when the bound field encrypter is exactly the package's own,
 * `SubjectKeyEncrypter`, or `NoFieldEncrypter`, which makes no key, so the keys
 * made before it was bound can still be erased. The class is compared exactly:
 * a subclass, a decorator or any other encrypter keeps its keys where the
 * package cannot see them, and is described by its type for the refusal that
 * names it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyStoreUse
{
    /** @var list<class-string<\SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter>> The encrypters that keep the package's key store in use. */
    private const array COVERED = [SubjectKeyEncrypter::class, NoFieldEncrypter::class];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the encrypter keeps the package's key store in use: it is exactly
     * the package's own encrypter or the one that never encrypts.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return bool
     */
    public static function covers(FieldEncrypter $encrypter): bool
    {
        return in_array($encrypter::class, self::COVERED, true);
    }

    /**
     * The encrypter as a refusal names it: its class, or the type an anonymous
     * class is declared as.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return string
     */
    public static function describe(FieldEncrypter $encrypter): string
    {
        return get_debug_type($encrypter);
    }
}
