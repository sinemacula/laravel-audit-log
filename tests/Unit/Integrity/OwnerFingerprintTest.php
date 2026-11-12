<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the owner fingerprint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerFingerprint::class)]
final class OwnerFingerprintTest extends TestCase
{
    /** @var string The ring key `k2026`'s secret. */
    private const string SECRET = 'audit-log golden key 0123456789!';

    /** @var string The ring key `k2025`'s secret. */
    private const string RETIRED_SECRET = 'audit-log retired key 0123456789';

    /**
     * The fingerprint is the keyed HMAC-SHA256 of the canonical owner, stable
     * and never the unkeyed digest.
     *
     * @return void
     */
    public function testTheFingerprintIsKeyedAndStable(): void
    {
        $fingerprints = new OwnerFingerprint(self::ring('k2026'));
        $owner        = Reference::of('App\Models\User', 7);
        $expected     = hash_hmac('sha256', '["App\\\Models\\\User","7"]', hash_hkdf('sha256', self::SECRET, 32, 'sinemacula/audit-log:owner:v1', ''));

        self::assertSame(['k2026', $expected], $fingerprints->of($owner));
        self::assertSame(['k2026', $expected], $fingerprints->of(Reference::of('App\Models\User', '7')));
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $expected);
        self::assertNotSame(hash('sha256', '["App\\\Models\\\User","7"]'), $expected);
        self::assertNotSame($expected, $fingerprints->of(Reference::of('App\Models\User', 8))[1]);
        self::assertNotSame($fingerprints->of(Reference::of('a', 'bc'))[1], $fingerprints->of(Reference::of('ab', 'c'))[1]);
        self::assertNotSame($fingerprints->of(Reference::of('a', 'b'))[1], $fingerprints->of(Reference::of('b', 'a'))[1]);
    }

    /**
     * A rotation of the ring changes the fingerprint and the key it names.
     *
     * @return void
     */
    public function testItChangesWithTheRingKey(): void
    {
        $owner  = Reference::of('App\Models\User', 7);
        $before = (new OwnerFingerprint(self::ring('k2025')))->of($owner);
        $after  = (new OwnerFingerprint(self::ring('k2026')))->of($owner);

        self::assertSame('k2025', $before[0]);
        self::assertSame('k2026', $after[0]);
        self::assertNotSame($before[1], $after[1]);
    }

    /**
     * The fingerprint key is HKDF-SHA256 of the secret under its pinned info
     * with an empty salt.
     *
     * @return void
     */
    public function testItIsDerivedUnderItsOwnInfo(): void
    {
        $key = OwnerFingerprint::key(self::SECRET);

        self::assertSame('sinemacula/audit-log:owner:v1', OwnerFingerprint::DERIVATION_INFO);
        self::assertSame(32, strlen($key));
        self::assertSame(hash_hkdf('sha256', self::SECRET, 32, 'sinemacula/audit-log:owner:v1', ''), $key);
        self::assertNotSame(self::SECRET, $key);
        self::assertNotSame(JournalSigner::key(self::SECRET), $key);
        self::assertNotSame(SealSigner::sealKey(self::SECRET), $key);
        self::assertNotSame(OwnerFingerprint::key(self::RETIRED_SECRET), $key);
    }

    /**
     * A fingerprint made before a rotation is made again under the key it names
     * while the ring keeps that key, and is refused once it does not.
     *
     * @return void
     */
    public function testUnderReproducesAnEarlierFingerprint(): void
    {
        $owner = Reference::of('App\Models\User', 7);

        [$keyId, $fingerprint] = (new OwnerFingerprint(self::ring('k2025')))->of($owner);

        $rotated = new OwnerFingerprint(self::ring('k2026'));

        self::assertSame($fingerprint, $rotated->under($keyId, $owner));
        self::assertSame($rotated->of($owner)[1], $rotated->under('k2026', $owner));
        self::assertNotSame($fingerprint, $rotated->under('k2026', $owner));

        $this->expectException(UnknownKeyException::class);

        $rotated->under('k1999', $owner);
    }

    /**
     * A ring derived from `app.key` fingerprints too, naming its derived key.
     *
     * @return void
     */
    public function testADerivedRingFingerprints(): void
    {
        $ring = new KeyRing(new IntegritySettings(new Repository(['app' => ['key' => 'base64:' . base64_encode(str_repeat('a', 32))]])));

        [$keyId, $fingerprint] = (new OwnerFingerprint($ring))->of(Reference::of('App\Models\User', 7));

        self::assertSame($ring->signingKey()->id, $keyId);
        self::assertSame($fingerprint, (new OwnerFingerprint($ring))->under($keyId, Reference::of('App\Models\User', 7)));
    }

    /**
     * The owner and the ring key are marked sensitive wherever they pass.
     *
     * @return void
     */
    public function testTheOwnerAndTheKeyAreMarkedSensitive(): void
    {
        foreach ([['key', 'secret'], ['of', 'owner'], ['under', 'owner'], ['fingerprint', 'owner'], ['fingerprint', 'key']] as [$method, $parameter]) {
            $reflected = new \ReflectionParameter([OwnerFingerprint::class, $method], $parameter);

            self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class), "{$method}() \${$parameter}");
        }
    }

    /**
     * A ring of the golden and the retired keys, signing with the one named.
     *
     * @param  string  $current
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(string $current): KeyRing
    {
        $keys = ['k2025' => self::RETIRED_SECRET, 'k2026' => self::SECRET];

        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => ['keys' => $keys, 'current' => $current]]])));
    }
}
