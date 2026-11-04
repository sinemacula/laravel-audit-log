<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Privacy\TypedPlaintext;

/**
 * Unit tests for the field cipher: the golden envelope opened and its field
 * key, additional data and ciphertext recomputed, a round trip, a fresh nonce
 * on every seal that no method takes, every authenticated part binding the
 * envelope, a field key per entry, the strict ciphertext, and canonical
 * additional data.
 *
 * The golden envelope is never sealed again with its fixed nonce through the
 * cipher, which takes none: it is opened, and its ciphertext is recomputed here
 * with `openssl_encrypt()` directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldCipher::class)]
final class FieldCipherTest extends TestCase
{
    /** @var string The golden field vector. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Privacy/field-v1.json';

    /** @var string Why an envelope does not open. */
    private const string UNOPENED = 'The envelope does not open under its key at its entry and path.';

    /** @var string A data key. */
    private const string DATA_KEY = 'field cipher test data key 32by!';

    /** @var string An entry id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-00000000000a';

    /** @var string Another entry id. */
    private const string OTHER_ENTRY_ID = '01932b4e-8a40-7000-8000-00000000000b';

    /** @var string A key row id. */
    private const string KEY_ID = '01932b4e-e000-7000-8000-000000000001';

    /** @var string A log id. */
    private const string LOG_ID = 'app-eu-1';

    /** @var list<int|string> A path. */
    private const array PATH = ['properties', 'items', 0, 'iban'];

    /**
     * The golden envelope opens to its plaintext under its data key, and its
     * field key, additional data and ciphertext are what the pinned derivation,
     * encoding and cipher give.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenVectorReproduces(): void
    {
        $golden   = self::golden();
        $dataKey  = (string) hex2bin($golden['data_key']);
        $envelope = $golden['envelope'];

        self::assertSame($golden['field_key'], bin2hex(FieldCipher::fieldKey($dataKey, $golden['entry_id'])));
        self::assertSame($golden['additional_data'], FieldCipher::additionalData($golden['log_id'], $golden['key_id'], 1, $golden['entry_id'], $golden['path']));
        self::assertSame($golden['plaintext'], TypedPlaintext::encode($golden['value']));
        $opened = FieldCipher::open($dataKey, $envelope['k'], $envelope['v'], $envelope['c'], $golden['entry_id'], $golden['path'], $golden['log_id']);

        self::assertSame($golden['plaintext'], $opened);

        $nonce = (string) hex2bin($golden['nonce']);
        $tag   = '';
        $key   = (string) hex2bin($golden['field_key']);
        $body  = (string) openssl_encrypt($golden['plaintext'], 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $golden['additional_data'], 16);

        self::assertSame($envelope['c'], self::base64url($nonce . $body . $tag));
        self::assertSame(['v' => 1, 'k' => $golden['key_id']], ['v' => $envelope['v'], 'k' => $envelope['k']]);
    }

    /**
     * Rows of `[plaintext]`: the shortest typed plaintext, a string, a map and
     * the longest.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePlaintexts(): iterable
    {
        yield from [
            'one digit'   => ['7'],
            'a string'    => ['"4242"'],
            'a map'       => ['{"a":[1,true,null]}'],
            'the longest' => ['"' . str_repeat('a', 1022) . '"'],
        ];
    }

    /**
     * A sealed plaintext opens to itself, in an envelope of exactly the
     * version, the key id and a base64url ciphertext of the nonce, the
     * plaintext's length and the tag.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('providePlaintexts')]
    public function testItRoundTrips(string $plaintext): void
    {
        $dataKey  = self::DATA_KEY;
        $envelope = FieldCipher::seal($dataKey, self::KEY_ID, $plaintext, self::ENTRY_ID, self::PATH, self::LOG_ID);

        self::assertSame(['v', 'k', 'c'], array_keys($envelope));
        self::assertSame(1, $envelope['v']);
        self::assertSame(self::KEY_ID, $envelope['k']);
        self::assertMatchesRegularExpression('/\A[A-Za-z0-9_-]+\z/', $envelope['c']);
        self::assertSame(12 + strlen($plaintext) + 16, strlen(self::decode($envelope['c'])));
        self::assertSame($plaintext, FieldCipher::open($dataKey, $envelope['k'], $envelope['v'], $envelope['c'], self::ENTRY_ID, self::PATH, self::LOG_ID));
    }

    /**
     * Every seal draws its own nonce: a thousand seals of the same plaintext
     * under the same key, entry and path repeat no nonce and no ciphertext.
     *
     * @return void
     */
    public function testANonceIsFreshEachTime(): void
    {
        $dataKey = self::DATA_KEY;
        $nonces  = [];
        $texts   = [];

        for ($seal = 0; $seal < 1000; $seal++) {
            $c = FieldCipher::seal($dataKey, self::KEY_ID, '"4242"', self::ENTRY_ID, self::PATH, self::LOG_ID)['c'];

            $nonces[] = substr(self::decode($c), 0, 12);
            $texts[]  = $c;
        }

        self::assertCount(1000, array_unique($nonces));
        self::assertCount(1000, array_unique($texts));
    }

    /**
     * No method of the cipher takes a nonce or an initialisation vector, so no
     * caller can make one repeat.
     *
     * @return void
     */
    public function testNoMethodTakesANonce(): void
    {
        $parameters = [];

        foreach ((new \ReflectionClass(FieldCipher::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                $parameters[] = strtolower($parameter->getName());
            }
        }

        self::assertContains('datakey', $parameters);
        $nonces = array_filter($parameters, static fn (string $name): bool => str_contains($name, 'nonce') || $name === 'iv' || str_contains($name, 'vector'));

        self::assertSame([], array_values($nonces));
    }

    /**
     * Rows of
     * `[what is changed, data key, key id, version, entry id, path, log id]`:
     * each authenticated part of an envelope changed in turn.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int, 3: string, 4: list<int|string>, 5: string}>
     */
    public static function provideChangedParts(): iterable
    {
        $key = str_repeat('k', 32);

        yield from [
            'another entry'                => [$key, self::KEY_ID, 1, self::OTHER_ENTRY_ID, self::PATH, self::LOG_ID],
            'another list position'        => [$key, self::KEY_ID, 1, self::ENTRY_ID, ['properties', 'items', 1, 'iban'], self::LOG_ID],
            'an index read as a map key'   => [$key, self::KEY_ID, 1, self::ENTRY_ID, ['properties', 'items', '0', 'iban'], self::LOG_ID],
            'another column'               => [$key, self::KEY_ID, 1, self::ENTRY_ID, ['context', 'items', 0, 'iban'], self::LOG_ID],
            'a shorter path'               => [$key, self::KEY_ID, 1, self::ENTRY_ID, ['properties', 'items', 0], self::LOG_ID],
            'another key id'               => [$key, '01932b4e-e000-7000-8000-000000000002', 1, self::ENTRY_ID, self::PATH, self::LOG_ID],
            'another version'              => [$key, self::KEY_ID, 2, self::ENTRY_ID, self::PATH, self::LOG_ID],
            'version zero'                 => [$key, self::KEY_ID, 0, self::ENTRY_ID, self::PATH, self::LOG_ID],
            'another log'                  => [$key, self::KEY_ID, 1, self::ENTRY_ID, self::PATH, 'app-us-1'],
            'another data key'             => [str_repeat('x', 32), self::KEY_ID, 1, self::ENTRY_ID, self::PATH, self::LOG_ID],
            'a data key differing at last' => [str_repeat('k', 31) . 'j', self::KEY_ID, 1, self::ENTRY_ID, self::PATH, self::LOG_ID],
        ];
    }

    /**
     * An envelope opens only with every authenticated part as it was sealed:
     * any change of the entry, the path, the key id, the version, the log or
     * the data key fails, naming nothing.
     *
     * @param  string  $dataKey
     * @param  string  $keyId
     * @param  int  $version
     * @param  string  $entryId
     * @param  list<int|string>  $path
     * @param  string  $logId
     * @return void
     */
    #[DataProvider('provideChangedParts')]
    public function testAnyChangedAuthenticatedPartFailsToOpen(string $dataKey, string $keyId, int $version, string $entryId, array $path, string $logId): void
    {
        $envelope = FieldCipher::seal(str_repeat('k', 32), self::KEY_ID, '"4242"', self::ENTRY_ID, self::PATH, self::LOG_ID);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::UNOPENED);

        FieldCipher::open($dataKey, $keyId, $version, $envelope['c'], $entryId, $path, $logId);
    }

    /**
     * A ciphertext with any byte changed, nonce, body or tag, fails to open.
     *
     * @return void
     */
    public function testAnyChangedByteFailsToOpen(): void
    {
        $dataKey = self::DATA_KEY;
        $sealed  = self::decode(FieldCipher::seal($dataKey, self::KEY_ID, '"4242"', self::ENTRY_ID, self::PATH, self::LOG_ID)['c']);

        foreach ([0, 11, 12, 17, strlen($sealed) - 16, strlen($sealed) - 1] as $position) {
            $tampered            = $sealed;
            $tampered[$position] = chr(ord($tampered[$position]) ^ 1);

            try {
                FieldCipher::open($dataKey, self::KEY_ID, 1, self::base64url($tampered), self::ENTRY_ID, self::PATH, self::LOG_ID);

                self::fail("Expected a change at byte {$position} to fail.");
            } catch (\UnexpectedValueException $exception) {
                self::assertSame(self::UNOPENED, $exception->getMessage());
            }
        }
    }

    /**
     * The field key is HKDF-SHA256 of the data key with the entry id as its
     * salt under its own info: one per entry, never the data key, and the same
     * for the same entry.
     *
     * @return void
     */
    public function testTheFieldKeyIsDerivedPerEntry(): void
    {
        $dataKey = self::DATA_KEY;
        $first   = FieldCipher::fieldKey($dataKey, self::ENTRY_ID);

        self::assertSame(32, strlen($first));
        self::assertSame(hash_hkdf('sha256', $dataKey, 32, 'sinemacula/audit-log:field-key:v1', self::ENTRY_ID), $first);
        self::assertSame($first, FieldCipher::fieldKey($dataKey, self::ENTRY_ID));
        self::assertNotSame($first, FieldCipher::fieldKey($dataKey, self::OTHER_ENTRY_ID));
        self::assertNotSame($dataKey, $first);
        self::assertNotSame(hash_hkdf('sha256', $dataKey, 32, 'sinemacula/audit-log:field-key:v1', ''), $first);
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
     * A data key that is not 32 bytes is refused before any key is derived, on
     * sealing and on opening, never padded or cut to fit.
     *
     * @param  string  $dataKey
     * @return void
     */
    #[DataProvider('provideMalformedDataKeys')]
    public function testADataKeyThatIsNot32BytesIsRefused(string $dataKey): void
    {
        $envelope = FieldCipher::seal(str_repeat('k', 32), self::KEY_ID, '"4242"', self::ENTRY_ID, self::PATH, self::LOG_ID);

        foreach (
            [
                static fn (): array => FieldCipher::seal($dataKey, self::KEY_ID, '"4242"', self::ENTRY_ID, self::PATH, self::LOG_ID),
                static fn (): string => FieldCipher::open($dataKey, self::KEY_ID, 1, $envelope['c'], self::ENTRY_ID, self::PATH, self::LOG_ID),
            ] as $call
        ) {
            try {
                $call();

                self::fail('Expected the data key to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A data key must be 32 bytes.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[plaintext]`: an empty plaintext and one a byte over the limit.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedPlaintexts(): iterable
    {
        yield from [
            'empty'         => [''],
            'one byte over' => ['"' . str_repeat('a', 1022) . '"a'],
        ];
    }

    /**
     * An empty plaintext and one over the typed limit are never sealed.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideRefusedPlaintexts')]
    public function testAPlaintextOutsideItsLengthIsRefused(string $plaintext): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A plaintext must be from 1 to 1024 bytes.');

        FieldCipher::seal(self::DATA_KEY, self::KEY_ID, $plaintext, self::ENTRY_ID, self::PATH, self::LOG_ID);
    }

    /**
     * Rows of `[how the ciphertext is made from a valid one]`: padding, the
     * standard alphabet, a length out of range, trailing bits that do not
     * re-encode, whitespace and nothing at all.
     *
     * @return iterable<string, array{0: \Closure(string): string}>
     */
    public static function provideMalformedCiphertexts(): iterable
    {
        yield from [
            'padded'                => [static fn (string $c): string => $c . '='],
            'the standard alphabet' => [static fn (string $c): string => strtr($c, '-_', '+/') . (str_contains($c, '-') || str_contains($c, '_') ? '' : '+')],
            'a leading space'       => [static fn (string $c): string => ' ' . $c],
            'a trailing newline'    => [static fn (string $c): string => $c . "\n"],
            'empty'                 => [static fn (string $c): string => ''],
            '28 bytes, too short'   => [static fn (string $c): string => self::base64url(str_repeat("\0", 28))],
            '1053 bytes, too long'  => [static fn (string $c): string => self::base64url(str_repeat("\0", 1053))],
            'a spare bit set'       => [static fn (string $c): string => substr($c, 0, -1) . self::withSpareBitFlipped(substr($c, -1))],
        ];
    }

    /**
     * A ciphertext that is not strict base64url of a nonce, a plaintext of 1 to
     * 1024 bytes and a tag, in the one form its bytes encode to, is refused
     * before anything is decrypted, naming nothing.
     *
     * @param  \Closure(string): string  $malform
     * @return void
     */
    #[DataProvider('provideMalformedCiphertexts')]
    public function testAMalformedCiphertextIsRefused(\Closure $malform): void
    {
        $dataKey = self::DATA_KEY;
        $c       = FieldCipher::seal($dataKey, self::KEY_ID, '"42"', self::ENTRY_ID, self::PATH, self::LOG_ID)['c'];

        self::assertSame(self::decode($c), self::decode(substr($c, 0, -1) . self::withSpareBitFlipped(substr($c, -1))));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::UNOPENED);

        FieldCipher::open($dataKey, self::KEY_ID, 1, $malform($c), self::ENTRY_ID, self::PATH, self::LOG_ID);
    }

    /**
     * A ciphertext whose length is at either end of the range is read, and
     * refused only by its authentication.
     *
     * @return void
     */
    public function testACiphertextAtEitherEndOfItsRangeIsReadToItsTag(): void
    {
        foreach ([29, 1052] as $length) {
            try {
                FieldCipher::open(self::DATA_KEY, self::KEY_ID, 1, self::base64url(str_repeat("\1", $length)), self::ENTRY_ID, self::PATH, self::LOG_ID);

                self::fail('Expected the forged ciphertext to fail its authentication.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame(self::UNOPENED, $exception->getMessage(), (string) $length);
            }
        }
    }

    /**
     * Rows of `[plaintext, version]`: envelopes that authenticate under their
     * data key and additional data but that the cipher never seals, an empty
     * plaintext, one over the typed limit and another version.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideAuthenticForgeries(): iterable
    {
        yield from [
            'an empty plaintext'      => ['', 1],
            'a byte over the limit'   => [str_repeat('a', 1025), 1],
            'version two of the same' => ['"4242"', 2],
        ];
    }

    /**
     * An envelope outside what version 1 seals is refused even when it
     * authenticates, made here with `openssl_encrypt()` under the field key and
     * the additional data it names.
     *
     * @param  string  $plaintext
     * @param  int  $version
     * @return void
     */
    #[DataProvider('provideAuthenticForgeries')]
    public function testAnAuthenticEnvelopeOutsideVersionOneIsRefused(string $plaintext, int $version): void
    {
        $nonce = str_repeat("\7", 12);
        $tag   = '';
        $data  = FieldCipher::additionalData(self::LOG_ID, self::KEY_ID, $version, self::ENTRY_ID, self::PATH);
        $body  = (string) openssl_encrypt($plaintext, 'aes-256-gcm', FieldCipher::fieldKey(self::DATA_KEY, self::ENTRY_ID), OPENSSL_RAW_DATA, $nonce, $tag, $data, 16);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::UNOPENED);

        FieldCipher::open(self::DATA_KEY, self::KEY_ID, $version, self::base64url($nonce . $body . $tag), self::ENTRY_ID, self::PATH, self::LOG_ID);
    }

    /**
     * The additional data is the canonical JSON of the domain, the entry, the
     * key id, the log, the path and the version, its keys sorted and a list
     * index kept an integer.
     *
     * @return void
     */
    public function testTheAdditionalDataIsCanonical(): void
    {
        $expected = '{"d":"sinemacula/audit-log:field:v1","entry":"' . self::ENTRY_ID . '","k":"' . self::KEY_ID . '","log":"app-eu-1",'
            . '"path":["properties","items",0,"iban"],"v":1}';

        self::assertSame($expected, FieldCipher::additionalData(self::LOG_ID, self::KEY_ID, 1, self::ENTRY_ID, self::PATH));
        self::assertSame('{"d":"sinemacula/audit-log:field:v1","entry":"e","k":"k","log":"l","path":["ip"],"v":1}', FieldCipher::additionalData('l', 'k', 1, 'e', ['ip']));
        self::assertNotSame(FieldCipher::additionalData('l', 'k', 1, 'e', ['properties', 0]), FieldCipher::additionalData('l', 'k', 1, 'e', ['properties', '0']));
    }

    /**
     * Rows of `[path]`: an empty path and paths that are not lists.
     *
     * @return iterable<string, array{0: array<array-key, int|string>}>
     */
    public static function provideNonListPaths(): iterable
    {
        yield from [
            'empty'        => [[]],
            'a map'        => [['column' => 'properties']],
            'out of order' => [[1 => 'card', 0 => 'properties']],
        ];
    }

    /**
     * A path that is empty or not a list is refused, so a path can never be
     * encoded as a map.
     *
     * @param  array<array-key, int|string>  $path
     * @return void
     */
    #[DataProvider('provideNonListPaths')]
    public function testAPathThatIsNotAListIsRefused(array $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A field\'s path must be a non-empty list.');

        FieldCipher::additionalData(self::LOG_ID, self::KEY_ID, 1, self::ENTRY_ID, $path);
    }

    /**
     * The constants are pinned.
     *
     * @return void
     */
    public function testTheConstantsArePinned(): void
    {
        self::assertSame([1, 12, 16, 32], [FieldCipher::VERSION, FieldCipher::NONCE_BYTES, FieldCipher::TAG_BYTES, FieldCipher::DATA_KEY_BYTES]);
    }

    /**
     * `FieldCipher` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(FieldCipher::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(FieldCipher::class, $instance);
    }

    /**
     * The golden vector.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{data_key: string, entry_id: string, path: list<int|string>, log_id: string, key_id: string, value: string, plaintext: string, field_key: string, additional_data: string, nonce: string, envelope: array{v: int, k: string, c: string}}
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
        /** @var array{data_key: string, entry_id: string, path: list<int|string>, log_id: string, key_id: string, value: string, plaintext: string, field_key: string, additional_data: string, nonce: string, envelope: array{v: int, k: string, c: string}} */
        return json_decode((string) file_get_contents(self::GOLDEN), true, 8, JSON_THROW_ON_ERROR);
        // phpcs:enable Generic.Files.LineLength.TooLong
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
     * The last character of a base64url text of 32 bytes with its lowest bit, a
     * spare bit no byte holds, flipped: the bytes it decodes to are the same,
     * but it is not the form they encode to.
     *
     * @param  string  $character
     * @return string
     */
    private static function withSpareBitFlipped(string $character): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

        return $alphabet[(int) strpos($alphabet, $character) ^ 1];
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
}
