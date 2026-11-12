<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeySettings;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException;
use SineMacula\Laravel\AuditLog\Keys\WrappingRing;

/**
 * Unit tests for the local key wrapper, pinned against a golden wrapped key.
 *
 * The wrapper takes no nonce, so the golden ciphertext is recomputed with
 * `openssl_encrypt()` directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LocalKeyWrapper::class)]
final class LocalKeyWrapperTest extends TestCase
{
    /** @var string The golden wrap vector. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Privacy/wrap-v1.json';

    /** @var string `app.key` as Laravel stores it. */
    private const string APP_KEY = 'base64:bGFyYXZlbC1hdWRpdC1sb2cgdGVzdCBrZXkhISEhISE=';

    /** @var string The golden wrapping secret, the ring key `w2026`. */
    private const string SECRET = 'audit-log golden wrap 0123456789';

    /** @var string A retired wrapping secret, the ring key `w2025`. */
    private const string RETIRED_SECRET = 'audit-log retired wrap 012345678';

    /** @var string The golden key row's id. */
    private const string KEY_ROW_ID = '01932b4e-e000-7000-8000-000000000001';

    /** @var string The golden key row's unit. */
    private const string UNIT = 'e04da77c985cc0ed5a98c5faf362eab7ebb34e4db753aef921fa2e05e6585a79';

    /** @var string A data key. */
    private const string DATA_KEY = 'local key wrapper test data key!';

    /** @var string A wrap context. */
    private const string CONTEXT = '{"d":"sinemacula/audit-log:wrap:v1","generation":1,"k":"k","unit":"u","wrap_key_id":"w2026"}';

    /** @var string Why a wrapped key does not unwrap. */
    private const string UNWRAPPED = 'The wrapped key does not unwrap under its wrapping key and context.';

    /**
     * A wrapped data key unwraps to itself under the same wrapping key and
     * context, as 80 characters of base64url.
     *
     * @return void
     */
    public function testItRoundTrips(): void
    {
        $wrapper = self::wrapper();
        $dataKey = self::DATA_KEY;
        $wrapped = $wrapper->wrap($dataKey, 'w2026', self::CONTEXT);

        self::assertSame(80, strlen($wrapped));
        self::assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{80}\z/', $wrapped);
        self::assertSame($dataKey, $wrapper->unwrap($wrapped, 'w2026', self::CONTEXT));
        self::assertSame($dataKey, $wrapper->unwrap($wrapper->wrap($dataKey, 'w2025', self::CONTEXT), 'w2025', self::CONTEXT));
    }

    /**
     * The golden wrapped key unwraps, and its AES key, context and ciphertext
     * match the pinned derivation.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenVectorReproduces(): void
    {
        $golden  = self::golden();
        $dataKey = (string) hex2bin($golden['data_key']);
        $aesKey  = hash_hkdf('sha256', $golden['secret'], 32, 'sinemacula/audit-log:wrap-key:v1', '');

        self::assertSame('sinemacula/audit-log:wrap-key:v1', LocalKeyWrapper::AES_KEY_INFO);
        self::assertSame($golden['aes_key'], bin2hex($aesKey));
        self::assertSame($golden['context'], SubjectKeyRow::wrapContextOf($golden['key_row_id'], $golden['unit'], $golden['generation'], $golden['wrap_key_id']));
        self::assertSame($dataKey, self::wrapper()->unwrap($golden['wrapped'], $golden['wrap_key_id'], $golden['context']));

        $nonce = (string) hex2bin($golden['nonce']);
        $tag   = '';
        $body  = (string) openssl_encrypt($dataKey, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $nonce, $tag, $golden['context'], 16);

        self::assertSame($golden['wrapped'], rtrim(strtr(base64_encode($nonce . $body . $tag), '+/', '-_'), '='));
    }

    /**
     * Rows of `[context]`: the golden context with each part it binds changed
     * in turn.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSubstitutedContexts(): iterable
    {
        yield from [
            'another row'          => [SubjectKeyRow::wrapContextOf('01932b4e-e000-7000-8000-000000000002', self::UNIT, 1, 'w2026')],
            'another unit'         => [SubjectKeyRow::wrapContextOf(self::KEY_ROW_ID, hash('sha256', 'another unit'), 1, 'w2026')],
            'another generation'   => [SubjectKeyRow::wrapContextOf(self::KEY_ROW_ID, self::UNIT, 2, 'w2026')],
            'another wrapping key' => [SubjectKeyRow::wrapContextOf(self::KEY_ROW_ID, self::UNIT, 1, 'w2025')],
            'no context'           => [''],
        ];
    }

    /**
     * The golden wrapped key does not unwrap under any other row, unit,
     * generation or wrapping key.
     *
     * @param  string  $context
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideSubstitutedContexts')]
    public function testASubstitutedContextFailsToUnwrap(string $context): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::UNWRAPPED);

        self::wrapper()->unwrap(self::golden()['wrapped'], 'w2026', $context);
    }

    /**
     * A key wrapped under one wrapping key does not unwrap under another, even
     * with the same context.
     *
     * @return void
     */
    public function testAWrappedKeyUnderAnotherIdFails(): void
    {
        $wrapped = self::wrapper()->wrap(self::DATA_KEY, 'w2025', self::CONTEXT);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::UNWRAPPED);

        self::wrapper()->unwrap($wrapped, 'w2026', self::CONTEXT);
    }

    /**
     * Every wrap draws its own nonce: wrapping the same key under the same
     * wrapping key and context two hundred times repeats no nonce and no text.
     *
     * @return void
     */
    public function testEachWrapUsesAFreshNonce(): void
    {
        $wrapper = self::wrapper();
        $dataKey = self::DATA_KEY;
        $nonces  = [];
        $texts   = [];

        for ($wrap = 0; $wrap < 200; $wrap++) {
            $wrapped = $wrapper->wrap($dataKey, 'w2026', self::CONTEXT);

            $nonces[] = substr($wrapped, 0, 16);
            $texts[]  = $wrapped;
        }

        self::assertCount(200, array_unique($nonces));
        self::assertCount(200, array_unique($texts));
    }

    /**
     * No method of the wrapper takes a nonce or an initialisation vector.
     *
     * @return void
     */
    public function testNoMethodTakesANonce(): void
    {
        $parameters = [];

        foreach ((new \ReflectionClass(LocalKeyWrapper::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                $parameters[] = strtolower($parameter->getName());
            }
        }

        self::assertContains('datakey', $parameters);
        $nonces = array_filter($parameters, static fn (string $name): bool => str_contains($name, 'nonce') || $name === 'iv' || str_contains($name, 'vector'));

        self::assertSame([], array_values($nonces));
    }

    /**
     * A wrapping key the ring does not hold is refused, wrapping and unwrapping
     * alike, naming the id alone.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnknownWrappingKeyIsRefused(): void
    {
        $wrapper = self::wrapper();

        foreach (
            [
                static fn (): string => $wrapper->wrap(self::DATA_KEY, 'w1999', self::CONTEXT),
                static fn (): string => $wrapper->unwrap(self::golden()['wrapped'], 'w1999', self::CONTEXT),
            ] as $call
        ) {
            try {
                $call();

                self::fail('Expected the unknown wrapping key to be refused.');
            } catch (UnknownWrappingKeyException $exception) {
                self::assertSame('w1999', $exception->keyId);
            }
        }
    }

    /**
     * The current key id is the ring's current key: the derived one without an
     * explicit ring, and the configured one with it.
     *
     * @return void
     */
    public function testTheCurrentKeyIdIsTheRings(): void
    {
        self::assertSame('w2026', self::wrapper()->currentKeyId());
        self::assertMatchesRegularExpression('/\Ad-[0-9a-f]{16}\z/', self::wrapper([])->currentKeyId());
        self::assertMatchesRegularExpression(KeyWrapper::KEY_ID_PATTERN, self::wrapper([])->currentKeyId());
    }

    /**
     * Rows of `[data key]`: data keys one byte short and one byte long.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedDataKeys(): iterable
    {
        yield from [
            'empty'          => [''],
            'one byte short' => [str_repeat('k', 31)],
            'one byte long'  => [str_repeat('k', 33)],
        ];
    }

    /**
     * A data key that is not 32 bytes is never wrapped.
     *
     * @param  string  $dataKey
     * @return void
     */
    #[DataProvider('provideMalformedDataKeys')]
    public function testADataKeyThatIsNot32BytesIsRefused(string $dataKey): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A data key must be 32 bytes.');

        self::wrapper()->wrap($dataKey, 'w2026', self::CONTEXT);
    }

    /**
     * Rows of `[how the text is made from the golden wrapped key]`.
     *
     * @return iterable<string, array{0: \Closure(string): string}>
     */
    public static function provideMalformedTexts(): iterable
    {
        yield from [
            'padded'                => [static fn (string $wrapped): string => $wrapped . '='],
            'the standard alphabet' => [static fn (string $wrapped): string => strtr($wrapped, '-_', '+/')],
            'a byte short'          => [static fn (string $wrapped): string => self::base64url(substr(self::decode($wrapped), 0, -1))],
            'a byte long'           => [static fn (string $wrapped): string => self::base64url(self::decode($wrapped) . "\0")],
            'a trailing newline'    => [static fn (string $wrapped): string => $wrapped . "\n"],
            'empty'                 => [static fn (string $wrapped): string => ''],
        ];
    }

    /**
     * A text that is not strict base64url of a nonce, a 32-byte key and a tag
     * is refused before any key is read.
     *
     * @param  \Closure(string): string  $malform
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideMalformedTexts')]
    public function testAMalformedTextIsRefused(\Closure $malform): void
    {
        $golden = self::golden();

        self::assertStringContainsString('_', $golden['wrapped']);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::UNWRAPPED);

        self::wrapper()->unwrap($malform($golden['wrapped']), 'w2026', $golden['context']);
    }

    /**
     * A failure shows neither the wrapped text, the data key nor the wrapping
     * secret in its message or frames.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAFailureNamesNothingOfTheKey(): void
    {
        $golden   = self::golden();
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            self::wrapper()->unwrap($golden['wrapped'], 'w2026', 'another context');

            self::fail('Expected the unwrap to fail.');
        } catch (\UnexpectedValueException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === LocalKeyWrapper::class);
            $shown  = $exception->getMessage() . print_r($frames, true);

            self::assertCount(2, $frames);
            self::assertStringContainsString(\SensitiveParameterValue::class, $shown);

            foreach ([$golden['wrapped'], self::SECRET, $golden['aes_key'], (string) hex2bin($golden['aes_key']), $golden['data_key']] as $hidden) {
                self::assertStringNotContainsString($hidden, $shown);
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * A refused data key shows nothing of the key in any frame.
     *
     * @return void
     */
    public function testARefusedDataKeyIsNotShown(): void
    {
        $dataKey  = 'a data key of 31 bytes, s3cr3t!';
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            self::wrapper()->wrap($dataKey, 'w2026', self::CONTEXT);

            self::fail('Expected the data key to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === LocalKeyWrapper::class);

            self::assertNotSame([], $frames);
            self::assertStringNotContainsString('s3cr3t', $exception->getMessage() . print_r($frames, true));
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * A wrapper over the golden and the retired explicit keys, or over the
     * privacy settings given.
     *
     * @param  ?array<string, array<string, string>|string>  $privacy
     * @return \SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper
     */
    private static function wrapper(?array $privacy = null): LocalKeyWrapper
    {
        $privacy ??= ['keys' => ['w2025' => self::RETIRED_SECRET, 'w2026' => self::SECRET], 'current' => 'w2026'];
        $config = new Repository(['audit-log' => ['privacy' => $privacy], 'app' => ['key' => self::APP_KEY]]);

        return new LocalKeyWrapper(new WrappingRing(new KeySettings($config, new IntegritySettings($config))));
    }

    /**
     * The bytes in base64url, with no padding.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * The bytes a base64url text encodes.
     *
     * @param  string  $text
     * @return string
     */
    private static function decode(string $text): string
    {
        return (string) base64_decode(strtr($text, '-_', '+/'), true);
    }

    /**
     * The golden wrap vector.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{wrap_key_id: string, secret: string, aes_key: string, data_key: string, key_row_id: string, unit: string, generation: int, context: string, nonce: string, wrapped: string}
     *
     * @throws \JsonException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function golden(): array
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        /** @var array{wrap_key_id: string, secret: string, aes_key: string, data_key: string, key_row_id: string, unit: string, generation: int, context: string, nonce: string, wrapped: string} */
        return json_decode((string) file_get_contents(self::GOLDEN), true, 8, JSON_THROW_ON_ERROR);
        // phpcs:enable Generic.Files.LineLength.TooLong
    }
}
