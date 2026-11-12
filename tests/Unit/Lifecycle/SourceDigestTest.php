<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\SourceDigest;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the keyed source digest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SourceDigest::class)]
final class SourceDigestTest extends TestCase
{
    /** @var string The current key's secret. */
    private const string SECRET = 'source digest current key 012345';

    /** @var string A retired key's secret. */
    private const string RETIRED_SECRET = 'source digest retired key 012345';

    /**
     * The digest is HMAC-SHA256 under a key of its own HKDF info.
     *
     * @return void
     */
    public function testTheDigestIsKeyedUnderItsOwnInfo(): void
    {
        $assertion = self::line()->assertion();
        $key       = hash_hkdf('sha256', self::SECRET, 32, 'sinemacula/audit-log:source-digest:v1', '');
        $digest    = self::digest()->of($assertion, 'k2');

        self::assertSame('sinemacula/audit-log:source-digest:v1', SourceDigest::DERIVATION_INFO);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode($assertion), $key), $digest);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $digest);
        self::assertNotSame(hash_hmac('sha256', CanonicalEncoder::encode($assertion), JournalSigner::key(self::SECRET)), $digest);
        self::assertNotSame(hash_hmac('sha256', CanonicalEncoder::encode($assertion), SealSigner::sealKey(self::SECRET)), $digest);
        self::assertNotSame(hash_hmac('sha256', CanonicalEncoder::encode($assertion), self::SECRET), $digest);
    }

    /**
     * One assertion under one key always gives one digest.
     *
     * @return void
     */
    public function testTheSameAssertionUnderTheSameKeyIsEqual(): void
    {
        self::assertSame(self::digest()->of(self::line()->assertion(), 'k2'), self::digest()->of(self::line()->assertion(), 'k2'));
        self::assertSame(self::digest()->of(self::line()->assertion(), 'k1'), self::digest()->of(self::line()->assertion(), 'k1'));
    }

    /**
     * The key changes the digest.
     *
     * @return void
     */
    public function testTheKeyChangesIt(): void
    {
        self::assertNotSame(self::digest()->of(self::line()->assertion(), 'k1'), self::digest()->of(self::line()->assertion(), 'k2'));
    }

    /**
     * Rows of `[field, value]`: each asserted field changed.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>|list<string>|string|null}>
     */
    public static function provideChangedFields(): iterable
    {
        yield from [
            'the code'            => ['event', 'invoice.rejected'],
            'the time'            => ['occurred_at', '2026-10-01T09:00:00.000002Z'],
            'the outcome'         => ['outcome', 'denied'],
            'the actor'           => ['actor', ['user', '43']],
            'the subject'         => ['subject', null],
            'the principal'       => ['principal', ['user', '42']],
            'the tenant'          => ['tenant', ['organisation', 'org_02']],
            'the reason'          => ['reason', 'over_budget'],
            'the correlation'     => ['correlation_id', 'app:ticket-124'],
            'the properties'      => ['properties', ['amount' => '1200.01']],
            'the context'         => ['context', ['route' => 'invoices.reject']],
            'the origin'          => ['origin', 'queue'],
            'the IP address'      => ['ip', '203.0.113.8'],
            'the version'         => ['v', '2'],
            'a type for an id'    => ['actor', ['user ', '42']],
            'an empty context'    => ['context', []],
            'no properties'       => ['properties', null],
            'a decimal\'s digits' => ['properties', ['amount' => '1200.0']],
        ];
    }

    /**
     * Any asserted field changed changes the digest.
     *
     * @param  string  $field
     * @param  array<string, string>|list<string>|string|null  $value
     * @return void
     */
    #[DataProvider('provideChangedFields')]
    public function testAnyChangedFieldChangesIt(string $field, array|string|null $value): void
    {
        $assertion = self::line()->assertion();
        $changed   = [...$assertion, $field => $value];

        self::assertNotSame(self::digest()->of($assertion, 'k2'), self::digest()->of($changed, 'k2'), $field);
    }

    /**
     * Minimisation and the category never change the digest.
     *
     * @return void
     */
    public function testMinimisationDoesNotChangeIt(): void
    {
        $line      = self::line(['password' => 'hunter2', 'amount' => '1200.00']);
        $key       = hash_hkdf('sha256', self::SECRET, 32, SourceDigest::DERIVATION_INFO, '');
        $recounted = new ImportLine(
            8,
            'crm-us',
            'us-east-1',
            'rec-9',
            $line->event,
            $line->occurredAt,
            $line->outcome,
            $line->reason,
            $line->actor,
            $line->subject,
            $line->principal,
            $line->tenant,
            'security',
            $line->correlationId,
            $line->properties,
            $line->context,
            $line->origin,
            $line->ip,
            5,
        );

        self::assertSame(['password' => 'hunter2', 'amount' => '1200.00'], $line->assertion()['properties']);
        self::assertSame('203.0.113.7', $line->assertion()['ip']);
        self::assertSame(hash_hmac('sha256', CanonicalEncoder::encode($line->assertion()), $key), self::digest()->of($line->assertion(), 'k2'));
        self::assertSame(self::digest()->of($line->assertion(), 'k2'), self::digest()->of($recounted->assertion(), 'k2'));
    }

    /**
     * A key the ring no longer holds is refused, naming the key's id.
     *
     * @return void
     */
    public function testAnUnknownKeyIsRefused(): void
    {
        $this->expectException(UnknownKeyException::class);

        self::digest()->of(self::line()->assertion(), 'k0');
    }

    /**
     * A new row's digest is taken under the ring's signing key.
     *
     * @return void
     */
    public function testTheSigningKeyIsTheRings(): void
    {
        self::assertSame('k2', self::digest()->signingKeyId());
    }

    /**
     * A digest over a ring of a retired key and the current one.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\SourceDigest
     */
    private static function digest(): SourceDigest
    {
        $settings = new IntegritySettings(new Repository(['audit-log' => ['integrity' => ['keys' => ['k1' => self::RETIRED_SECRET, 'k2' => self::SECRET], 'current' => 'k2']]]));

        return new SourceDigest(new KeyRing($settings));
    }

    /**
     * A line asserting an approval, with the properties given.
     *
     * @param  array<string, string>  $properties
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(array $properties = ['amount' => '1200.00']): ImportLine
    {
        return new ImportLine(
            number: 1,
            sourceId: 'crm-eu',
            sourceRegion: null,
            sourceRecordId: 'rec-1',
            event: 'invoice.approved',
            occurredAt: '2026-10-01T09:00:00.000001Z',
            outcome: Outcome::FAILURE,
            reason: 'over_limit',
            actor: Reference::of('user', '42'),
            subject: Reference::of('invoice', 'inv_0042'),
            principal: null,
            tenant: Reference::of('organisation', 'org_01'),
            category: 'finance',
            correlationId: 'app:ticket-123',
            properties: $properties,
            context: ['route' => 'invoices.approve'],
            origin: 'http',
            ip: '203.0.113.7',
        );
    }
}
