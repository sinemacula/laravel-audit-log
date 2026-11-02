<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Config\SecretSetting;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;

/**
 * Unit tests for the integrity settings: the explicit ring and its current key,
 * the application keys the default ring is derived from, the strict decoding of
 * every secret, the message each malformed value fails closed with, and the
 * secrets no message or stack trace ever shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegritySettings::class)]
final class IntegritySettingsTest extends TestCase
{
    /** @var string The test `app.key`, as Laravel writes it. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string The bytes the test `app.key` decodes to. */
    private const string APP_KEY_BYTES = 'laravel-audit-log test key!!!!!!';

    /** @var string An explicit secret given as its own 32 bytes. */
    private const string RAW_SECRET = 'explicit-ring-secret-of-32-bytes';

    /** @var string An explicit secret given as `base64:` of 32 bytes of 0xAB. */
    private const string BASE64_SECRET = 'base64:q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=';

    /** @var string The `audit-log.integrity.keys` refusal. */
    private const string KEYS_NOT_A_MAP = '`audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.';

    /** @var string The refusal of a key id outside the pattern. */
    private const string BAD_ID = '`audit-log.integrity.keys` has a key id that is not 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

    /** @var string The refusal of a malformed secret, by key id. */
    private const string BAD_SECRET = '`audit-log.integrity.keys.%s` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.';

    /** @var string The refusal of a current key id the ring does not hold. */
    private const string CURRENT_NOT_IN_RING = '`audit-log.integrity.current` must name a key in `audit-log.integrity.keys`.';

    /** @var string The refusal of a current key id beside an empty ring. */
    private const string CURRENT_WITHOUT_KEYS = '`audit-log.integrity.current` names a key, but `audit-log.integrity.keys` is empty;'
        . ' set both, or neither to derive the key from `app.key`.';

    /** @var string The refusal of a missing `app.key`. */
    private const string APP_KEY_MISSING = '`app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.';

    /** @var string The refusal of a short or undecodable `app.key`. */
    private const string APP_KEY_MALFORMED = '`app.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes, to derive the integrity key.';

    /** @var string The refusal of malformed `app.previous_keys`. */
    private const string PREVIOUS_KEYS_MALFORMED = '`app.previous_keys` must be a list of keys of at least 32 bytes each,'
        . ' or `base64:` followed by the encoding of one, to derive the keys that verify older rows.';

    /**
     * With neither `keys` nor `current` set, or with both empty, no explicit
     * ring is configured and no key id is current.
     *
     * @return void
     */
    public function testWithoutKeysNoExplicitRingIsConfigured(): void
    {
        foreach (['unset' => [], 'null' => ['keys' => null, 'current' => null], 'empty' => ['keys' => [], 'current' => '']] as $case => $integrity) {
            $settings = self::settings($integrity);

            self::assertSame([], $settings->explicitKeys(), $case);
            self::assertNull($settings->currentKeyId(), $case);

            $settings->validate();
        }
    }

    /**
     * An explicit secret given as its own bytes is kept, and one given as
     * `base64:` is decoded strictly to its bytes.
     *
     * @return void
     */
    public function testExplicitSecretsAreDecoded(): void
    {
        $settings = self::settings(['keys' => ['raw' => self::RAW_SECRET, 'encoded' => self::BASE64_SECRET], 'current' => 'raw']);

        self::assertSame(['raw' => self::RAW_SECRET, 'encoded' => str_repeat("\xAB", 32)], $settings->explicitKeys());
    }

    /**
     * A key id PHP stores as an integer key counts as its string, both in the
     * ring and when `current` names it.
     *
     * @return void
     */
    public function testANumericKeyIdIsReadAsAString(): void
    {
        $settings = self::settings(['keys' => ['2026' => self::RAW_SECRET, 7 => self::BASE64_SECRET], 'current' => '2026']);

        self::assertSame(['2026', '7'], array_map(strval(...), array_keys($settings->explicitKeys())));
        self::assertSame(self::RAW_SECRET, $settings->explicitKeys()[2026]);
        self::assertSame('2026', $settings->currentKeyId());

        $settings->validate();
    }

    /**
     * The current key id is read as given when the ring holds it.
     *
     * @return void
     */
    public function testTheCurrentKeyIdIsRead(): void
    {
        $settings = self::settings(['keys' => ['old' => self::BASE64_SECRET, 'new' => self::RAW_SECRET], 'current' => 'old']);

        self::assertSame('old', $settings->currentKeyId());
    }

    /**
     * An empty `current`, which an empty environment line gives, reads as none:
     * without keys the key is derived, and with keys it is the "must name a
     * key" refusal, never matched against a key id.
     *
     * @return void
     */
    public function testAnEmptyCurrentKeyIdReadsAsNone(): void
    {
        $derived = self::settings(['keys' => [], 'current' => '']);

        self::assertNull($derived->currentKeyId());

        $derived->validate();

        $explicit = self::settings(['keys' => ['k1' => self::RAW_SECRET], 'current' => '']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::CURRENT_NOT_IN_RING);

        $explicit->currentKeyId();
    }

    /**
     * Rows of `[integrity settings, message]`: every malformed explicit ring or
     * current key id, and the message it fails with.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedRings(): iterable
    {
        yield from [
            'keys a string'                  => [['keys' => 'k1'], self::KEYS_NOT_A_MAP],
            'keys an empty string'           => [['keys' => ''], self::KEYS_NOT_A_MAP],
            'keys true'                      => [['keys' => true], self::KEYS_NOT_A_MAP],
            'keys an integer'                => [['keys' => 1], self::KEYS_NOT_A_MAP],
            'an id with a leading dot'       => [['keys' => ['.k1' => self::RAW_SECRET], 'current' => '.k1'], self::BAD_ID],
            'an id of 33 characters'         => [['keys' => [str_repeat('k', 33) => self::RAW_SECRET]], self::BAD_ID],
            'an id with a space'             => [['keys' => ['k 1' => self::RAW_SECRET]], self::BAD_ID],
            'an empty id'                    => [['keys' => ['' => self::RAW_SECRET]], self::BAD_ID],
            'a negative integer id'          => [['keys' => [-1 => self::RAW_SECRET]], self::BAD_ID],
            'a secret not a string'          => [['keys' => ['k1' => 12345678901234567], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a null secret'                  => [['keys' => ['k1' => null], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a list secret'                  => [['keys' => ['k1' => [self::RAW_SECRET]], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'an empty secret'                => [['keys' => ['k1' => ''], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a 31-byte secret'               => [['keys' => ['k1' => str_repeat('s', 31)], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a base64 secret of 31 bytes'    => [['keys' => ['k1' => 'base64:' . base64_encode(str_repeat('s', 31))], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a secret that does not decode'  => [['keys' => ['k1' => 'base64:' . str_repeat('!', 44)], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a bare base64 prefix'           => [['keys' => ['k1' => 'base64:'], 'current' => 'k1'], sprintf(self::BAD_SECRET, 'k1')],
            'a bad entry beside a good one'  => [['keys' => ['good' => self::RAW_SECRET, 'bad' => 'short'], 'current' => 'good'], sprintf(self::BAD_SECRET, 'bad')],
            'a numeric id with a bad secret' => [['keys' => [2026 => 'short'], 'current' => '2026'], sprintf(self::BAD_SECRET, '2026')],
            'current not a string'           => [['keys' => ['1' => self::RAW_SECRET], 'current' => 1], self::CURRENT_NOT_IN_RING],
            'current a list'                 => [['keys' => ['k1' => self::RAW_SECRET], 'current' => ['k1']], self::CURRENT_NOT_IN_RING],
            'current null with keys'         => [['keys' => ['k1' => self::RAW_SECRET], 'current' => null], self::CURRENT_NOT_IN_RING],
            'current unset with keys'        => [['keys' => ['k1' => self::RAW_SECRET]], self::CURRENT_NOT_IN_RING],
            'current naming no key'          => [['keys' => ['k1' => self::RAW_SECRET], 'current' => 'k2'], self::CURRENT_NOT_IN_RING],
            'current differing in case'      => [['keys' => ['k1' => self::RAW_SECRET], 'current' => 'K1'], self::CURRENT_NOT_IN_RING],
            'current a padded numeric id'    => [['keys' => [2026 => self::RAW_SECRET], 'current' => '02026'], self::CURRENT_NOT_IN_RING],
            'current empty with keys'        => [['keys' => ['k1' => self::RAW_SECRET], 'current' => ''], self::CURRENT_NOT_IN_RING],
            'current not a string, no keys'  => [['current' => 1], self::CURRENT_NOT_IN_RING],
            'current with empty keys'        => [['keys' => [], 'current' => 'k1'], self::CURRENT_WITHOUT_KEYS],
            'current with keys unset'        => [['current' => 'k1'], self::CURRENT_WITHOUT_KEYS],
        ];
    }

    /**
     * Each malformed ring or current key id fails closed with its message from
     * `currentKeyId()` and `validate()`, even beside a valid `app.key`, so no
     * reader ever falls back to the derived ring.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedRings')]
    public function testAMalformedRingFailsClosedNamingTheSetting(array $integrity, string $message): void
    {
        $settings = self::settings($integrity);

        self::assertRefused($message, $settings->currentKeyId(...));
        self::assertRefused($message, $settings->validate(...));
    }

    /**
     * A malformed ring fails closed from `explicitKeys()` too, whatever the
     * current key id.
     *
     * @return void
     */
    public function testAMalformedRingFailsClosedFromTheRing(): void
    {
        self::assertRefused(self::KEYS_NOT_A_MAP, self::settings(['keys' => 'k1'])->explicitKeys(...));
        self::assertRefused(self::BAD_ID, self::settings(['keys' => ['k/1' => self::RAW_SECRET]])->explicitKeys(...));
        self::assertRefused(sprintf(self::BAD_SECRET, 'k1'), self::settings(['keys' => ['k1' => 'short']])->explicitKeys(...));
    }

    /**
     * The application keys are `app.key` decoded, then each previous key
     * decoded, in their order, raw and `base64:` forms alike.
     *
     * @return void
     */
    public function testTheApplicationKeysAreTheCurrentKeyThenThePreviousOnes(): void
    {
        $previous = [self::RAW_SECRET, 'base64:' . base64_encode(str_repeat("\0", 32)), self::APP_KEY];
        $settings = self::settings([], ['key' => self::APP_KEY, 'previous_keys' => $previous]);

        self::assertSame([self::APP_KEY_BYTES, self::RAW_SECRET, str_repeat("\0", 32), self::APP_KEY_BYTES], $settings->applicationKeys());

        $settings->validate();
    }

    /**
     * `app.key` alone is the one application key when `app.previous_keys` is
     * unset, `null` or empty, and a raw `app.key` is its own bytes.
     *
     * @return void
     */
    public function testWithoutPreviousKeysTheApplicationKeyIsAlone(): void
    {
        $cases = [
            'unset' => ['key' => self::APP_KEY_BYTES],
            'null'  => ['key' => self::APP_KEY_BYTES, 'previous_keys' => null],
            'empty' => ['key' => self::APP_KEY_BYTES, 'previous_keys' => []],
        ];

        foreach ($cases as $case => $app) {
            self::assertSame([self::APP_KEY_BYTES], self::settings([], $app)->applicationKeys(), $case);
        }
    }

    /**
     * Rows of `[app.key, message]`: every malformed `app.key`, and the message
     * it fails with.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedApplicationKeys(): iterable
    {
        yield from [
            'missing'                     => [null, self::APP_KEY_MISSING],
            'empty'                       => ['', self::APP_KEY_MISSING],
            'an integer'                  => [12345678901234567, self::APP_KEY_MISSING],
            'a list'                      => [[self::APP_KEY], self::APP_KEY_MISSING],
            'short'                       => ['short', self::APP_KEY_MALFORMED],
            '31 bytes'                    => [str_repeat('k', 31), self::APP_KEY_MALFORMED],
            'base64 of 31 bytes'          => ['base64:' . base64_encode(str_repeat('k', 31)), self::APP_KEY_MALFORMED],
            'base64 that does not decode' => ['base64:' . str_repeat('*', 44), self::APP_KEY_MALFORMED],
            'a bare base64 prefix'        => ['base64:', self::APP_KEY_MALFORMED],
        ];
    }

    /**
     * Each malformed `app.key` fails closed from `applicationKeys()` and from
     * `validate()` when no explicit ring is set.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $key
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedApplicationKeys')]
    public function testAMalformedApplicationKeyFailsClosed(mixed $key, string $message): void
    {
        $settings = self::settings([], ['key' => $key]);

        self::assertRefused($message, $settings->applicationKeys(...));
        self::assertRefused($message, $settings->validate(...));
    }

    /**
     * Rows of `[app.previous_keys]`: previous keys that are not a list, or hold
     * an entry that is not a string, is short or does not decode.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedPreviousKeys(): iterable
    {
        yield from [
            'a string'                      => [self::APP_KEY],
            'an empty string'               => [''],
            'true'                          => [true],
            'a map'                         => [['old' => self::APP_KEY]],
            'a list with a gap'             => [[0 => self::APP_KEY, 2 => self::RAW_SECRET]],
            'an integer entry'              => [[12345678901234567]],
            'a null entry'                  => [[null]],
            'an empty entry'                => [['']],
            'a short entry'                 => [['short']],
            'a base64 entry of 31 bytes'    => [['base64:' . base64_encode(str_repeat('p', 31))]],
            'an entry that does not decode' => [['base64:' . str_repeat('*', 44)]],
            'a bad entry after good ones'   => [[self::APP_KEY, self::RAW_SECRET, 'short']],
        ];
    }

    /**
     * Malformed previous keys fail closed from `applicationKeys()` and from
     * `validate()` when no explicit ring is set.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $previous
     * @return void
     */
    #[DataProvider('provideMalformedPreviousKeys')]
    public function testMalformedPreviousKeysFailClosed(mixed $previous): void
    {
        $settings = self::settings([], ['key' => self::APP_KEY, 'previous_keys' => $previous]);

        self::assertRefused(self::PREVIOUS_KEYS_MALFORMED, $settings->applicationKeys(...));
        self::assertRefused(self::PREVIOUS_KEYS_MALFORMED, $settings->validate(...));
    }

    /**
     * Beside a valid explicit ring, `validate()` never reads the application
     * keys: an empty `app.key` and malformed previous keys validate.
     *
     * @return void
     */
    public function testValidateLeavesTheApplicationKeyAloneForAnExplicitRing(): void
    {
        $settings = self::settings(['keys' => ['k1' => self::RAW_SECRET], 'current' => 'k1'], ['key' => '', 'previous_keys' => 'malformed']);

        $settings->validate();

        self::assertSame(['k1' => self::RAW_SECRET], $settings->explicitKeys());
        self::assertRefused(self::APP_KEY_MISSING, $settings->applicationKeys(...));
    }

    /**
     * Settings are read on every call, so a change to the configuration is seen
     * by the next call without a new instance.
     *
     * @return void
     */
    public function testSettingsAreReadOnEveryCall(): void
    {
        $config   = new Repository(['audit-log' => ['integrity' => ['keys' => [], 'current' => null]], 'app' => ['key' => self::APP_KEY]]);
        $settings = new IntegritySettings($config);

        self::assertNull($settings->currentKeyId());

        $config->set('audit-log.integrity.keys', ['k1' => self::RAW_SECRET]);
        $config->set('audit-log.integrity.current', 'k1');
        $config->set('app.key', self::RAW_SECRET);

        self::assertSame('k1', $settings->currentKeyId());
        self::assertSame([self::RAW_SECRET], $settings->applicationKeys());
    }

    /**
     * Rows of `[integrity settings, app settings, secret]`: every refusal of a
     * secret or an application key, and the secret it must never show.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: string}>
     */
    public static function provideRefusedSecrets(): iterable
    {
        $short   = 'leaked-short-secret';
        $encoded = 'base64:' . base64_encode($short);
        $broken  = 'base64:leaked*secret';

        yield from [
            'a short secret'                  => [['keys' => ['k1' => $short], 'current' => 'k1'], [], $short],
            'a base64 short secret'           => [['keys' => ['k1' => $encoded], 'current' => 'k1'], [], $encoded],
            'a secret that does not decode'   => [['keys' => ['k1' => $broken], 'current' => 'k1'], [], $broken],
            'a short app.key'                 => [[], ['key' => $short], $short],
            'a base64 short app.key'          => [[], ['key' => $encoded], $encoded],
            'an app.key that does not decode' => [[], ['key' => $broken], $broken],
            'a short previous key'            => [[], ['key' => self::APP_KEY, 'previous_keys' => [$short]], $short],
            'a base64 short previous key'     => [[], ['key' => self::APP_KEY, 'previous_keys' => [$encoded]], $encoded],
            'previous keys as a string'       => [[], ['key' => self::APP_KEY, 'previous_keys' => $short], $short],
        ];
    }

    /**
     * No refusal shows the secret, its `base64:` form or its decoded bytes, in
     * its message or in the arguments of the settings' own frames of its stack
     * trace, and none shows the valid keys beside it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $app
     * @param  string  $secret
     * @return void
     */
    #[DataProvider('provideRefusedSecrets')]
    public function testNoMessageContainsASecret(array $integrity, array $app, string $secret): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            self::settings($integrity, $app + ['key' => self::APP_KEY])->validate();
            self::fail('Expected the secret to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === IntegritySettings::class);
            $shown  = $exception->getMessage() . print_r($frames, true);

            self::assertNotSame([], $frames);

            foreach ([$secret, 'leaked', base64_encode('leaked-short-secret'), self::APP_KEY, self::APP_KEY_BYTES, 'bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE'] as $hidden) {
                self::assertStringNotContainsString($hidden, $shown);
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * The decoding helper marks its value sensitive, as does the helper that
     * reads an explicit secret, so a stack trace through either never shows the
     * key material.
     *
     * @return void
     */
    public function testTheDecodingHelperMarksItsValueSensitive(): void
    {
        $decoded = (new \ReflectionMethod(SecretSetting::class, 'decode'))->getParameters()[0];
        $secret  = (new \ReflectionMethod(IntegritySettings::class, 'secret'))->getParameters()[1];

        self::assertSame('value', $decoded->getName());
        self::assertNotSame([], $decoded->getAttributes(\SensitiveParameter::class));
        self::assertSame('secret', $secret->getName());
        self::assertNotSame([], $secret->getAttributes(\SensitiveParameter::class));
    }

    /**
     * Assert the call fails closed with exactly the message.
     *
     * @param  string  $message
     * @param  \Closure(): void  $call
     * @return void
     */
    private static function assertRefused(string $message, \Closure $call): void
    {
        try {
            $call();
            self::fail(sprintf('Expected the call to be refused with: %s', $message));
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * Settings over a plain repository holding the integrity settings and the
     * application settings given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $integrity
     * @param  array<string, mixed>  $app
     * @return \SineMacula\Laravel\AuditLog\Integrity\IntegritySettings
     */
    private static function settings(array $integrity, array $app = ['key' => self::APP_KEY]): IntegritySettings
    {
        return new IntegritySettings(new Repository(['audit-log' => ['integrity' => $integrity], 'app' => $app]));
    }
}
