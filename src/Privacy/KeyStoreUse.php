<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;

/**
 * Whether the package's key store is in use, which erasure, the owner trail
 * filter and key verification rely on.
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
     * Whether the encrypter's class is exactly one that keeps the key store in
     * use; a subclass or decorator keeps its keys elsewhere.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return bool
     */
    public static function covers(FieldEncrypter $encrypter): bool
    {
        return in_array($encrypter::class, self::COVERED, true);
    }

    /**
     * The encrypter as a refusal names it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return string
     */
    public static function describe(FieldEncrypter $encrypter): string
    {
        return get_debug_type($encrypter);
    }
}
