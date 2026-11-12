<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Keys\KeySettings;
use SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException;
use SineMacula\Laravel\AuditLog\Keys\WrappingRing;

/**
 * Unit tests for the wrapping ring and the keys it derives from `app.key` or
 * reads explicitly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WrappingRing::class)]
final class WrappingRingTest extends TestCase
{
    /** @var string The golden wrap vector. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Privacy/wrap-v1.json';

    /** @var string `app.key` as Laravel stores it. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string A previous application key. */
    private const string PREVIOUS_KEY = 'previous-application-key-32-byte';

    /** @var string An explicit wrapping secret. */
    private const string OLD_SECRET = 'explicit-wrap-old-secret-32-byte';

    /** @var string Another explicit wrapping secret. */
    private const string NEW_SECRET = 'explicit-wrap-new-secret-32-byte';

    /**
     * Without an explicit ring the wrapping key is HKDF-SHA256 of `app.key`,
     * its id `d-` and 16 hex characters of an HMAC.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheDerivedIdIsADashedFingerprint(): void
    {
        $derived = self::golden()['derived'];
        $key     = self::ring([])->current();
        $secret  = hash_hkdf('sha256', 'laravel-audit-log test key!!!!!!', 32, 'sinemacula/audit-log:subject-wrap:v1', '');

        self::assertSame('sinemacula/audit-log:subject-wrap:v1', WrappingRing::DERIVATION_INFO);
        self::assertSame(self::APP_KEY, $derived['app_key']);
        self::assertSame($derived['id'], $key->id);
        self::assertSame($derived['secret'], bin2hex($key->secret()));
        self::assertSame($secret, $key->secret());
        self::assertSame('d-' . substr(hash_hmac('sha256', 'audit-log:wrap-key-id', $secret), 0, 16), $key->id);
        self::assertMatchesRegularExpression('/\Ad-[0-9a-f]{16}\z/', $key->id);
        self::assertSame($key->id, self::ring([])->key($key->id)->id);
    }

    /**
     * A rotated `app.key` wraps under a new id, and the previous key stays in
     * the ring under its own id for unwrapping what it wrapped.
     *
     * @return void
     */
    public function testARotatedAppKeyKeepsThePreviousForUnwrapping(): void
    {
        $before  = self::ring([], ['key' => self::PREVIOUS_KEY])->current();
        $rotated = self::ring([], ['key' => self::APP_KEY, 'previous_keys' => [self::PREVIOUS_KEY]]);

        self::assertNotSame($before->id, $rotated->current()->id);
        self::assertSame($before->id, $rotated->key($before->id)->id);
        self::assertSame($before->secret(), $rotated->key($before->id)->secret());
        self::assertSame($rotated->current()->secret(), $rotated->key($rotated->current()->id)->secret());

        $this->expectException(UnknownWrappingKeyException::class);

        self::ring([])->key($before->id);
    }

    /**
     * An explicit ring wraps with its current key and keeps every key for
     * unwrapping, a numeric id included.
     *
     * @return void
     */
    public function testAnExplicitRingWrapsWithItsCurrentKey(): void
    {
        $ring = self::ring(['keys' => ['w2025' => self::OLD_SECRET, 2026 => self::NEW_SECRET], 'current' => '2026']);

        self::assertSame('2026', $ring->current()->id);
        self::assertSame(self::NEW_SECRET, $ring->current()->secret());
        self::assertSame(self::OLD_SECRET, $ring->key('w2025')->secret());
        self::assertSame(self::NEW_SECRET, $ring->key('2026')->secret());
    }

    /**
     * An explicit ring never falls back to `app.key`: its current key wraps,
     * and a malformed explicit ring fails closed rather than deriving.
     *
     * @return void
     */
    public function testAnExplicitRingNeverFallsBackToTheAppKey(): void
    {
        $derivedId = self::ring([])->current()->id;
        $explicit  = self::ring(['keys' => ['w2026' => self::NEW_SECRET], 'current' => 'w2026']);

        self::assertSame('w2026', $explicit->current()->id);
        self::assertNotSame($derivedId, $explicit->current()->id);

        foreach ([['keys' => ['w2026' => 'short'], 'current' => 'w2026'], ['current' => 'w2026']] as $malformed) {
            foreach ([static fn (WrappingRing $ring): string => $ring->current()->id, static fn (WrappingRing $ring): string => $ring->key($derivedId)->id] as $call) {
                try {
                    $call(self::ring($malformed));

                    self::fail('Expected the malformed ring to fail closed.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertStringStartsWith('`audit-log.privacy.', $exception->getMessage());
                }
            }
        }
    }

    /**
     * An explicit ring still unwraps keys derived from `app.key`, listed after
     * its own, so a rewrap can move them, but never wraps under them.
     *
     * @return void
     */
    public function testAnExplicitRingStillUnwrapsADerivedKey(): void
    {
        $derived  = self::ring([], ['key' => self::APP_KEY, 'previous_keys' => [self::PREVIOUS_KEY]]);
        $current  = $derived->current();
        $previous = self::ring([], ['key' => self::PREVIOUS_KEY])->current();
        $ring     = ['keys' => ['w2025' => self::OLD_SECRET, 'w2026' => self::NEW_SECRET], 'current' => 'w2026'];
        $explicit = self::ring($ring, ['key' => self::APP_KEY, 'previous_keys' => [self::PREVIOUS_KEY]]);

        self::assertSame('w2026', $explicit->current()->id);
        self::assertSame($current->secret(), $explicit->key($current->id)->secret());
        self::assertSame($previous->secret(), $explicit->key($previous->id)->secret());
        self::assertSame(['w2026', 'w2025', $current->id, $previous->id], $explicit->ids());
        self::assertSame([$current->id, $previous->id], $derived->ids());
    }

    /**
     * An explicit ring is read without `app.key`: a missing or malformed
     * application key adds no derived key and refuses nothing.
     *
     * @return void
     */
    public function testAnExplicitRingIgnoresTheApplicationKey(): void
    {
        foreach ([[], ['key' => 'short'], ['key' => self::APP_KEY, 'previous_keys' => 'x']] as $app) {
            $ring = self::ring(['keys' => ['w2026' => self::NEW_SECRET], 'current' => 'w2026'], $app);

            self::assertSame('w2026', $ring->current()->id);
            self::assertSame('w2026', $ring->key('w2026')->id);
            self::assertSame(['w2026'], $ring->ids());
        }
    }

    /**
     * A key id the ring does not hold is refused naming the id.
     *
     * @return void
     */
    public function testAnUnknownIdIsRefused(): void
    {
        foreach ([self::ring([]), self::ring(['keys' => ['w2026' => self::NEW_SECRET], 'current' => 'w2026'])] as $ring) {
            try {
                $ring->key('w1999');

                self::fail('Expected the unknown key to be refused.');
            } catch (UnknownWrappingKeyException $exception) {
                self::assertSame('w1999', $exception->keyId);
            }
        }
    }

    /**
     * The derivation differs from the integrity ring's, so the integrity and
     * wrapping keys are never one key.
     *
     * @return void
     */
    public function testTheDerivationIsSeparateFromTheIntegrityRing(): void
    {
        $wrapping  = self::ring([])->current();
        $integrity = (new KeyRing(new IntegritySettings(new Repository(['app' => ['key' => self::APP_KEY]]))))->signingKey();

        self::assertNotSame($integrity->secret(), $wrapping->secret());
        self::assertNotSame($integrity->id, $wrapping->id);
        self::assertStringStartsNotWith('d-', $integrity->id);
    }

    /**
     * Nothing is cached: a change to the settings is seen by the next call on
     * the same ring.
     *
     * @return void
     */
    public function testNothingIsCached(): void
    {
        $config = new Repository(['audit-log' => ['privacy' => []], 'app' => ['key' => self::APP_KEY]]);
        $ring   = new WrappingRing(new KeySettings($config, new IntegritySettings($config)));
        $first  = $ring->current();

        $config->set('app.key', self::PREVIOUS_KEY);

        self::assertNotSame($first->id, $ring->current()->id);

        $config->set('audit-log.privacy.keys', ['w2026' => self::NEW_SECRET]);
        $config->set('audit-log.privacy.current', 'w2026');

        self::assertSame('w2026', $ring->current()->id);
        self::assertSame(self::NEW_SECRET, $ring->key('w2026')->secret());
    }

    /**
     * The derivation marks the application key sensitive.
     *
     * @return void
     */
    public function testDerivationMarksTheApplicationKeySensitive(): void
    {
        $parameter = (new \ReflectionMethod(WrappingRing::class, 'derive'))->getParameters()[0];

        self::assertSame('applicationKey', $parameter->getName());
        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A ring over the privacy and application settings given.
     *
     * @param  array<string, array<int|string, string>|string>  $privacy
     * @param  array<string, list<string>|string>  $app
     * @return \SineMacula\Laravel\AuditLog\Keys\WrappingRing
     */
    private static function ring(array $privacy, array $app = ['key' => self::APP_KEY]): WrappingRing
    {
        $config = new Repository(['audit-log' => ['privacy' => $privacy], 'app' => $app]);

        return new WrappingRing(new KeySettings($config, new IntegritySettings($config)));
    }

    /**
     * The golden wrap vector.
     *
     * @return array{derived: array{app_key: string, secret: string, id: string}}
     *
     * @throws \JsonException
     */
    private static function golden(): array
    {
        /** @var array{derived: array{app_key: string, secret: string, id: string}} */
        return json_decode((string) file_get_contents(self::GOLDEN), true, 8, JSON_THROW_ON_ERROR);
    }
}
