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
 * Unit tests for the terms a read's record names and their fingerprints.
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
     * Each fingerprint is a hex HMAC-SHA256 under an HKDF key of its own info.
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
     * No fingerprint is a plain SHA-256 a reader could match by guessing.
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
     * The same key gives the same fingerprints, and another key others.
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
     * With no scope answered, the scope's fingerprint is `null`.
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
     * The data owner is part of the fingerprinted filters.
     *
     * @return void
     */
    public function testTheOwnerHoldingDataIsFingerprinted(): void
    {
        $key     = new IntegrityKey('ring-1', self::SECRET);
        $owner   = self::filters()->withHoldingDataOf(Reference::of('App\Models\User', '42'));
        $other   = self::filters()->withHoldingDataOf(Reference::of('App\Models\User', '43'));
        $again   = self::filters()->withHoldingDataOf(Reference::of('App\Models\User', '41'))->withHoldingDataOf(Reference::of('App\Models\User', '42'));
        $derived = hash_hkdf('sha256', self::SECRET, 32, ReadTerms::DERIVATION_INFO, '');
        $terms   = ReadTerms::of($key, $owner, self::scope());

        self::assertSame(['App\Models\User', '42'], $owner->normalised()['holding_data_of']);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode(['filters' => $owner->normalised()]), $derived), $terms->queryFingerprint);
        self::assertNotSame($terms->queryFingerprint, ReadTerms::of($key, $other, self::scope())->queryFingerprint);
        self::assertNotSame($terms->queryFingerprint, ReadTerms::of($key, self::filters(), self::scope())->queryFingerprint);
        self::assertSame($terms->queryFingerprint, ReadTerms::of($key, $again, self::scope())->queryFingerprint);
        self::assertSame($terms->scopeFingerprint, ReadTerms::of($key, self::filters(), self::scope())->scopeFingerprint);
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
