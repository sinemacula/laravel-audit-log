<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Querying\ReadTerms;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the terms a read's record names: the filters and the scope as
 * given, their fingerprints keyed under a key HKDF derives from the ring key's
 * secret with an info string of the fingerprints' own, never a plain digest of
 * the canonical forms anyone could compute, and the key's id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadTerms::class)]
final class ReadTermsTest extends TestCase
{
    /** @var string The secret of the ring key the terms are keyed by. */
    private const string SECRET = 'a-ring-key-secret-of-thirty-two-bytes-or-more';

    /**
     * Each fingerprint is the lower-case hex HMAC-SHA256 of the canonical
     * encoding of the normalised filters, or the scope, under its own label,
     * keyed by the HKDF-SHA256 of the ring key's secret with an empty salt and
     * the info `sinemacula/audit-log:fingerprint:v1`; the terms keep the
     * filters, the scope and the key's id.
     *
     * @return void
     */
    public function testTheFingerprintsAreKeyedHmacs(): void
    {
        $filters = self::filters();
        $scope   = self::scope();
        $terms   = ReadTerms::of(new IntegrityKey('ring-1', self::SECRET), $filters, $scope);
        $key     = hash_hkdf('sha256', self::SECRET, 32, 'sinemacula/audit-log:fingerprint:v1', '');

        self::assertSame('sinemacula/audit-log:fingerprint:v1', ReadTerms::DERIVATION_INFO);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode(['filters' => $filters->normalised()]), $key), $terms->queryFingerprint);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode(['scope' => $scope->toArray()]), $key), $terms->scopeFingerprint);
        self::assertSame(['ring-1', $filters, $scope], [$terms->keyId, $terms->filters, $terms->scope]);
    }

    /**
     * No fingerprint is the plain SHA-256 of a canonical form, which a reader
     * of the record could compute for candidate tenants and ids until one
     * matched, and the scope's is not the unkeyed one a cursor binds.
     *
     * @return void
     */
    public function testNoFingerprintIsAPlainDigest(): void
    {
        $terms = ReadTerms::of(new IntegrityKey('ring-1', self::SECRET), self::filters(), self::scope());

        self::assertNotSame(hash('sha256', CanonicalEncoder::encode(self::filters()->normalised())), $terms->queryFingerprint);
        self::assertNotSame(hash('sha256', CanonicalEncoder::encode(self::scope()->toArray())), $terms->scopeFingerprint);
        self::assertNotSame(self::scope()->fingerprint(), $terms->scopeFingerprint);
    }

    /**
     * Another key gives other fingerprints of the same terms, and the same key
     * the same ones, so reads under one key compare and nothing else does.
     *
     * @return void
     */
    public function testTheFingerprintsFollowTheKey(): void
    {
        $first   = ReadTerms::of(new IntegrityKey('ring-1', self::SECRET), self::filters(), self::scope());
        $again   = ReadTerms::of(new IntegrityKey('ring-1', self::SECRET), self::filters(), self::scope());
        $rotated = ReadTerms::of(new IntegrityKey('ring-2', self::SECRET . '!'), self::filters(), self::scope());

        self::assertSame([$first->queryFingerprint, $first->scopeFingerprint], [$again->queryFingerprint, $again->scopeFingerprint]);
        self::assertNotSame($first->queryFingerprint, $rotated->queryFingerprint);
        self::assertNotSame($first->scopeFingerprint, $rotated->scopeFingerprint);
        self::assertSame('ring-2', $rotated->keyId);
    }

    /**
     * With no scope answered the scope's fingerprint is `null`; the filters are
     * still fingerprinted.
     *
     * @return void
     */
    public function testNoScopeHasNoFingerprint(): void
    {
        $terms = ReadTerms::of(new IntegrityKey('ring-1', self::SECRET), self::filters(), null);

        self::assertNull($terms->scope);
        self::assertNull($terms->scopeFingerprint);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $terms->queryFingerprint);
    }

    /**
     * The key is a sensitive parameter.
     *
     * @return void
     */
    public function testTheKeyIsSensitive(): void
    {
        $parameter = (new \ReflectionMethod(ReadTerms::class, 'of'))->getParameters()[0];

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The filters the terms are of: one code and a tenant.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailFilters
     */
    private static function filters(): TrailFilters
    {
        return TrailFilters::none()->withEvents(['invoice.approved'])->withReference('tenant', Reference::of('organisation', '7'));
    }

    /**
     * The scope the terms are of: two tenants.
     *
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    private static function scope(): AccessScope
    {
        return AccessScope::tenants(Reference::of('organisation', '7'), Reference::of('organisation', '8'));
    }
}
