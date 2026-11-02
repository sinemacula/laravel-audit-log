<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Unit tests for the key ring: the keys it derives from the application keys,
 * pinned byte for byte, the previous keys that verify but never sign, the
 * explicit ring that signs with its current key and never falls back to
 * `app.key`, the malformed rings that fail closed on every call, and the key
 * ids it reports as unknown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyRing::class)]
final class KeyRingTest extends TestCase
{
    /** @var string The test `app.key`, as Laravel writes it. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string The bytes the test `app.key` decodes to. */
    private const string APP_KEY_BYTES = 'laravel-audit-log test key!!!!!!';

    /** @var string The id of the key derived from the test `app.key`. */
    private const string DERIVED_ID = 'd03d4735ce37bd961';

    /** @var string The secret of the key derived from the test `app.key`, in hex. */
    private const string DERIVED_SECRET = '7a165658ad4b0b4330b915223278dc4f4423d77eff72753e95ce069bc01f65ac';

    /** @var string An `app.key` of 32 zero bytes, as `base64:`. */
    private const string ZERO_APP_KEY = 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

    /** @var string The id of the key derived from 32 zero bytes. */
    private const string ZERO_ID = 'd456bb9a43d6f0486';

    /** @var string The secret of the key derived from 32 zero bytes, in hex. */
    private const string ZERO_SECRET = '0e4b1a85cabcb610d6da5a6075c55fb3d1e8ec8a11973d4620f5594cca3556e1';

    /** @var string An explicit secret given as its own 32 bytes. */
    private const string OLD_SECRET = 'explicit-ring-old-secret-32-byte';

    /** @var string Another explicit secret given as its own 32 bytes. */
    private const string NEW_SECRET = 'explicit-ring-new-secret-32-byte';

    /**
     * With no explicit ring, one key is derived from `app.key`; it signs, and
     * it is the key of its id.
     *
     * @return void
     */
    public function testTheDefaultDerivesOneSigningKeyFromTheApplicationKey(): void
    {
        $ring = self::ring([]);

        $signing = $ring->signingKey();

        self::assertSame(self::DERIVED_ID, $signing->id);
        self::assertSame(32, strlen($signing->secret()));
        self::assertNotSame(self::APP_KEY_BYTES, $signing->secret());
        self::assertSame($signing->secret(), $ring->key(self::DERIVED_ID)->secret());
        self::assertSame(self::DERIVED_ID, $ring->key(self::DERIVED_ID)->id);
    }

    /**
     * The key derived from a fixed application key is pinned: HKDF-SHA256 with
     * the version 1 info and no salt, and its id the fingerprint of its secret,
     * for the test `app.key` and for 32 zero bytes.
     *
     * @return void
     */
    public function testTheDerivedKeyIsStableForAFixedApplicationKey(): void
    {
        $test = self::ring([])->signingKey();
        $zero = self::ring([], ['key' => self::ZERO_APP_KEY])->signingKey();

        self::assertSame(self::DERIVED_ID, $test->id);
        self::assertSame(self::DERIVED_SECRET, bin2hex($test->secret()));
        self::assertSame(self::ZERO_ID, $zero->id);
        self::assertSame(self::ZERO_SECRET, bin2hex($zero->secret()));
        self::assertSame(hash_hkdf('sha256', self::APP_KEY_BYTES, 32, 'sinemacula/audit-log:integrity:v1', ''), $test->secret());
        self::assertSame('d' . substr(hash_hmac('sha256', 'audit-log:key-id', $test->secret()), 0, 16), $test->id);
    }

    /**
     * A `base64:` application key is decoded before derivation: its raw bytes
     * and its `base64:` form give one key.
     *
     * @return void
     */
    public function testABase64ApplicationKeyIsDecodedBeforeDerivation(): void
    {
        $raw     = self::ring([], ['key' => self::APP_KEY_BYTES])->signingKey();
        $encoded = self::ring([], ['key' => self::APP_KEY])->signingKey();

        self::assertSame(self::DERIVED_ID, $raw->id);
        self::assertSame($encoded->id, $raw->id);
        self::assertSame($encoded->secret(), $raw->secret());
    }

    /**
     * A rotated `app.key` derives a key with a new id, so rows signed before
     * the rotation keep naming the old one.
     *
     * @return void
     */
    public function testARotatedApplicationKeyGetsANewKeyId(): void
    {
        $before = self::ring([], ['key' => self::APP_KEY])->signingKey();
        $after  = self::ring([], ['key' => self::ZERO_APP_KEY])->signingKey();

        self::assertSame(self::DERIVED_ID, $before->id);
        self::assertSame(self::ZERO_ID, $after->id);
        self::assertNotSame($before->secret(), $after->secret());
    }

    /**
     * Each previous application key derives a key that verifies its rows, and
     * only `app.key`'s key signs.
     *
     * @return void
     */
    public function testPreviousApplicationKeysVerifyButNeverSign(): void
    {
        $ring = self::ring([], ['key' => self::ZERO_APP_KEY, 'previous_keys' => [self::APP_KEY, self::OLD_SECRET]]);

        $older = hash_hkdf('sha256', self::OLD_SECRET, 32, 'sinemacula/audit-log:integrity:v1', '');
        $id    = 'd' . substr(hash_hmac('sha256', 'audit-log:key-id', $older), 0, 16);

        self::assertSame(self::ZERO_ID, $ring->signingKey()->id);
        self::assertSame(self::ZERO_SECRET, bin2hex($ring->key(self::ZERO_ID)->secret()));
        self::assertSame(self::DERIVED_SECRET, bin2hex($ring->key(self::DERIVED_ID)->secret()));
        self::assertSame($older, $ring->key($id)->secret());
        self::assertSame($id, $ring->key($id)->id);
    }

    /**
     * A previous key equal to `app.key` derives the same key, which is
     * harmless: the key of its id is that key.
     *
     * @return void
     */
    public function testAPreviousKeyEqualToTheApplicationKeyIsHarmless(): void
    {
        $ring = self::ring([], ['key' => self::APP_KEY, 'previous_keys' => [self::APP_KEY_BYTES]]);

        self::assertSame(self::DERIVED_ID, $ring->signingKey()->id);
        self::assertSame(self::DERIVED_SECRET, bin2hex($ring->key(self::DERIVED_ID)->secret()));
    }

    /**
     * An explicit ring signs with its current key, whose secret is used as
     * given, never derived.
     *
     * @return void
     */
    public function testAnExplicitRingSignsWithTheCurrentKey(): void
    {
        $ring = self::ring(['keys' => ['old' => self::OLD_SECRET, 'new' => self::NEW_SECRET], 'current' => 'new']);

        $signing = $ring->signingKey();

        self::assertSame('new', $signing->id);
        self::assertSame(self::NEW_SECRET, $signing->secret());
    }

    /**
     * Every key of an explicit ring verifies, a `base64:` secret as its decoded
     * bytes, whichever key signs.
     *
     * @return void
     */
    public function testAnExplicitRingKeepsEveryKeyForVerification(): void
    {
        $encoded = 'base64:' . base64_encode(str_repeat("\x07", 40));
        $ring    = self::ring(['keys' => ['old' => self::OLD_SECRET, 'encoded' => $encoded, 'new' => self::NEW_SECRET], 'current' => 'new']);

        self::assertSame(self::OLD_SECRET, $ring->key('old')->secret());
        self::assertSame(str_repeat("\x07", 40), $ring->key('encoded')->secret());
        self::assertSame(self::NEW_SECRET, $ring->key('new')->secret());
        self::assertSame('old', $ring->key('old')->id);
    }

    /**
     * A key id PHP stores as an integer key is the key of its string id, and
     * signs as that string.
     *
     * @return void
     */
    public function testANumericKeyIdIsTheKeyOfItsString(): void
    {
        $ring = self::ring(['keys' => [2026 => self::OLD_SECRET, 7 => self::NEW_SECRET], 'current' => '2026']);

        self::assertSame('2026', $ring->signingKey()->id);
        self::assertSame(self::OLD_SECRET, $ring->signingKey()->secret());
        self::assertSame(self::NEW_SECRET, $ring->key('7')->secret());
    }

    /**
     * Beside an explicit ring, the key derived from `app.key` is unknown: the
     * ring never falls back to the application key.
     *
     * @return void
     */
    public function testAnExplicitRingNeverFallsBackToTheApplicationKey(): void
    {
        $ring = self::ring(['keys' => ['k1' => self::OLD_SECRET], 'current' => 'k1'], ['key' => self::APP_KEY, 'previous_keys' => [self::ZERO_APP_KEY]]);

        self::assertSame('k1', $ring->signingKey()->id);

        foreach ([self::DERIVED_ID, self::ZERO_ID] as $id) {
            try {
                $ring->key($id);
                self::fail(sprintf('Expected the derived key [%s] to be unknown beside an explicit ring.', $id));
            } catch (UnknownKeyException $exception) {
                self::assertSame($id, $exception->keyId);
            }
        }
    }

    /**
     * An explicit ring never reads the application keys, so a malformed
     * `app.key` or previous key beside it signs and verifies.
     *
     * @return void
     */
    public function testAnExplicitRingIgnoresAMalformedApplicationKey(): void
    {
        $ring = self::ring(['keys' => ['k1' => self::OLD_SECRET], 'current' => 'k1'], ['key' => 'short', 'previous_keys' => 'malformed']);

        self::assertSame(self::OLD_SECRET, $ring->signingKey()->secret());
        self::assertSame(self::OLD_SECRET, $ring->key('k1')->secret());
    }

    /**
     * Rows of `[integrity settings, a valid key id]`: explicit rings that are
     * malformed, and the id of a well-formed entry in them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedExplicitRings(): iterable
    {
        yield from [
            'a malformed entry beside a valid one' => [['keys' => ['good' => self::OLD_SECRET, 'bad' => 'short'], 'current' => 'good'], 'good'],
            'a malformed id beside a valid one'    => [['keys' => ['good' => self::OLD_SECRET, 'b/d' => self::NEW_SECRET], 'current' => 'good'], 'good'],
            'a short secret'                       => [['keys' => ['k1' => str_repeat('s', 31)], 'current' => 'k1'], 'k1'],
            'current naming no key'                => [['keys' => ['k1' => self::OLD_SECRET], 'current' => 'k2'], 'k1'],
            'current empty with keys'              => [['keys' => ['k1' => self::OLD_SECRET], 'current' => ''], 'k1'],
            'current null with keys'               => [['keys' => ['k1' => self::OLD_SECRET], 'current' => null], 'k1'],
            'keys not a map'                       => [['keys' => self::OLD_SECRET, 'current' => 'k1'], 'k1'],
            'current with no keys'                 => [['keys' => [], 'current' => 'k1'], 'k1'],
        ];
    }

    /**
     * A malformed explicit ring signs nothing and verifies nothing: the signing
     * key, a well-formed entry's key and the derived key each fail closed,
     * never returning a derived key, though `app.key` is valid.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideMalformedExplicitRings')]
    public function testAMalformedExplicitRingFailsClosedOnEveryCall(array $integrity, string $id): void
    {
        $ring = self::ring($integrity);

        $calls = [
            'signingKey()'      => $ring->signingKey(...),
            'key() of an entry' => static fn (): IntegrityKey => $ring->key($id),
            'key() derived'     => static fn (): IntegrityKey => $ring->key(self::DERIVED_ID),
        ];

        foreach ($calls as $call => $closure) {
            try {
                $closure();
                self::fail(sprintf('Expected %s to fail closed.', $call));
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith('`audit-log.integrity.', $exception->getMessage(), $call);
            }
        }
    }

    /**
     * Without an explicit ring, a malformed `app.key` or previous key fails
     * closed on every call: nothing signs and nothing verifies.
     *
     * @return void
     */
    public function testAMalformedApplicationKeyFailsClosedOnEveryCall(): void
    {
        $rings = [
            'a short app.key'        => self::ring([], ['key' => 'short']),
            'a missing app.key'      => self::ring([], []),
            'a short previous key'   => self::ring([], ['key' => self::APP_KEY, 'previous_keys' => ['short']]),
            'previous keys not list' => self::ring([], ['key' => self::APP_KEY, 'previous_keys' => self::ZERO_APP_KEY]),
        ];

        foreach ($rings as $case => $ring) {
            foreach (['signingKey()' => $ring->signingKey(...), 'key()' => static fn (): IntegrityKey => $ring->key(self::DERIVED_ID)] as $call => $closure) {
                try {
                    $closure();
                    self::fail(sprintf('Expected %s to fail closed with %s.', $call, $case));
                } catch (\InvalidArgumentException $exception) {
                    self::assertStringStartsWith('`app.', $exception->getMessage(), $case . ' ' . $call);
                }
            }
        }
    }

    /**
     * Rows of `[integrity settings]`: a derived ring and an explicit ring.
     *
     * @return iterable<string, array{0: array<string, array<string, string>|string>}>
     */
    public static function provideRings(): iterable
    {
        yield from [
            'a derived ring'   => [[]],
            'an explicit ring' => [['keys' => ['k1' => self::OLD_SECRET], 'current' => 'k1']],
        ];
    }

    /**
     * A key id the ring does not hold is reported as unknown, keeping the id,
     * derived and explicit alike.
     *
     * @param  array<string, array<string, string>|string>  $integrity
     * @return void
     */
    #[DataProvider('provideRings')]
    public function testAnUnknownKeyIdIsReportedAsUnknown(array $integrity): void
    {
        try {
            self::ring($integrity)->key('retired-2025');
            self::fail('Expected the key id to be unknown.');
        } catch (UnknownKeyException $exception) {
            self::assertSame('retired-2025', $exception->keyId);
            self::assertSame('The integrity key [retired-2025] is not in the key ring; its rows cannot be verified until it is configured again.', $exception->getMessage());
        }
    }

    /**
     * The ring is rebuilt from the settings on every call, so a rotated key
     * signs the next record without a new ring.
     *
     * @return void
     */
    public function testTheRingIsRebuiltOnEveryCall(): void
    {
        $config = new Repository(['audit-log' => ['integrity' => ['keys' => [], 'current' => null]], 'app' => ['key' => self::APP_KEY]]);
        $ring   = new KeyRing(new IntegritySettings($config));

        self::assertSame(self::DERIVED_ID, $ring->signingKey()->id);

        $config->set('app.key', self::ZERO_APP_KEY);

        self::assertSame(self::ZERO_ID, $ring->signingKey()->id);

        $config->set('audit-log.integrity.keys', ['k1' => self::OLD_SECRET]);
        $config->set('audit-log.integrity.current', 'k1');

        self::assertSame('k1', $ring->signingKey()->id);
        self::assertSame(self::OLD_SECRET, $ring->key('k1')->secret());
    }

    /**
     * Derivation marks the application key sensitive, so a stack trace through
     * it never shows the key.
     *
     * @return void
     */
    public function testDerivationMarksTheApplicationKeySensitive(): void
    {
        $parameter = (new \ReflectionMethod(KeyRing::class, 'derive'))->getParameters()[0];

        self::assertSame('applicationKey', $parameter->getName());
        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A key ring over a plain repository holding the integrity settings and the
     * application settings given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $app
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $integrity, array $app = ['key' => self::APP_KEY]): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity], 'app' => $app])));
    }
}
