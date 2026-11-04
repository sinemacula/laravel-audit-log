<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\IpMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\OmissionLog;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Privacy\SealingScope;
use SineMacula\Laravel\AuditLog\Privacy\TypedPlaintext;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\MalformedFieldEncrypter;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;

/**
 * Unit tests for the IP minimiser: the canonical form, what each mode stores,
 * the IPv4-mapped rule, invalid addresses, and an encrypted address as
 * canonical JSON that fits its column or is dropped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IpMinimiser::class)]
final class IpMinimiserTest extends TestCase
{
    /** @var string The root key of the golden hashes. */
    private const string ROOT_KEY = '0123456789abcdef0123456789abcdef';

    /** @var string The golden hash of `203.0.113.7`. */
    private const string IPV4_HASH = '05d70d576b2b05d5:d8cd13f098906335536b7d3cff22a70c382c0d3a2a4c38cbd2815e6a456118e1';

    /** @var string The golden hash of `2001:db8::1`. */
    private const string IPV6_HASH = '05d70d576b2b05d5:70ba167d07452e86911ea28f6f4067e2c9963f07d216a158ee83f07f6371c95a';

    /** @var string The golden hash of `2001:db8:abcd:12::1`. */
    private const string LONGER_IPV6_HASH = '05d70d576b2b05d5:cc7a0619e29485b78ffeb1ab29c86e6585cf1b9693ecff15b791f519884383dd';

    /** @var int How many bytes an envelope of `k` as its key and version 1 encodes to with an empty ciphertext. */
    private const int ENVELOPE_FRAME_BYTES = 22;

    /** @var string The id of the entry every address is sealed for. */
    private const string ENTRY_ID = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

    /** @var array{count: int, paths: list<string>} What the log holds once an address was not stored. */
    private const array DIAGNOSED = ['count' => 1, 'paths' => ['$ip']];

    /**
     * Rows of `[input, full, truncate, hash]`: the mode matrix over IPv4, IPv6
     * and both spellings of an IPv4-mapped address.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string}>
     */
    public static function provideAddresses(): iterable
    {
        yield from [
            'IPv4'                  => ['203.0.113.7', '203.0.113.7', '203.0.113.0', self::IPV4_HASH],
            'IPv6'                  => ['2001:db8:abcd:12::1', '2001:db8:abcd:12::1', '2001:db8:abcd::', self::LONGER_IPV6_HASH],
            'mapped, dotted'        => ['::ffff:203.0.113.7', '203.0.113.7', '203.0.113.0', self::IPV4_HASH],
            'mapped, hexadecimal'   => ['::FFFF:CB00:7107', '203.0.113.7', '203.0.113.0', self::IPV4_HASH],
            'mapped, written out'   => ['0:0:0:0:0:ffff:cb00:7107', '203.0.113.7', '203.0.113.0', self::IPV4_HASH],
            'IPv6, upper case'      => ['2001:DB8::1', '2001:db8::1', '2001:db8::', self::IPV6_HASH],
            'IPv6, written in full' => ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1', '2001:db8::', self::IPV6_HASH],
        ];
    }

    /**
     * Each mode stores what the matrix says, drops nothing it should keep, and
     * touches neither the encrypter nor the log.
     *
     * @param  string  $input
     * @param  string  $full
     * @param  string  $truncate
     * @param  string  $hash
     * @return void
     */
    #[DataProvider('provideAddresses')]
    public function testTheModeMatrix(string $input, string $full, string $truncate, string $hash): void
    {
        $expected = [
            IpMode::FULL->value     => $full,
            IpMode::TRUNCATE->value => $truncate,
            IpMode::HASH->value     => $hash,
            IpMode::DROP->value     => null,
        ];

        foreach ($expected as $mode => $stored) {
            $encrypter = new RecordingFieldEncrypter;
            $omissions = new OmissionLog;

            self::assertSame($stored, self::minimiser($mode)->minimise($input, self::actor(), self::sealer($encrypter), $omissions, self::scope()), $mode);
            self::assertSame([], $encrypter->calls(), $mode);
            self::assertNull($omissions->toArray(), $mode);
        }
    }

    /**
     * Rows of `[input, canonical]`: addresses that look mapped or sit near the
     * edge of the prefix and are not mapped, so they stay IPv6.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnmappedAddresses(): iterable
    {
        yield from [
            'the loopback'                 => ['::1', '::1'],
            'the unspecified address'      => ['::', '::'],
            'the prefix after a first hex' => ['1::ffff:cb00', '1::ffff:cb00'],
            'the translated prefix'        => ['::ffff:0:cb00:7107', '::ffff:0:cb00:7107'],
            'a mapped-looking tail'        => ['2001:db8::ffff:cb00:7107', '2001:db8::ffff:cb00:7107'],
        ];
    }

    /**
     * Only the whole `::ffff:0:0/96` prefix, at the start, makes an address
     * IPv4; protects against a mutation that looks for it anywhere.
     *
     * @param  string  $input
     * @param  string  $canonical
     * @return void
     */
    #[DataProvider('provideUnmappedAddresses')]
    public function testAnAddressOutsideTheMappedPrefixStaysIpv6(string $input, string $canonical): void
    {
        self::assertSame($canonical, IpMinimiser::canonical($input));
    }

    /**
     * The edge of the mapped range becomes the edge of IPv4.
     *
     * @return void
     */
    public function testTheEdgesOfTheMappedRangeBecomeIpv4(): void
    {
        self::assertSame('0.0.0.0', IpMinimiser::canonical('::ffff:0:0'));
        self::assertSame('255.255.255.255', IpMinimiser::canonical('::ffff:ffff:ffff'));
    }

    /**
     * Rows of `[input, network]`: every byte past the network is zeroed, and
     * every byte within it is kept.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideNetworks(): iterable
    {
        yield from [
            'IPv4, every bit set'     => ['255.255.255.255', '255.255.255.0'],
            'IPv4, the last byte set' => ['0.0.0.255', '0.0.0.0'],
            'IPv6, every bit set'     => ['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ffff:ffff:ffff::'],
            'IPv6, the 49th bit set'  => ['2001:db8:abcd:8000::', '2001:db8:abcd::'],
            'IPv6, the 48th bit set'  => ['2001:db8:1::', '2001:db8:1::'],
            'IPv6, the loopback'      => ['::1', '::'],
            '6to4'                    => ['2002:cb00:7107:1234::5', '2002:cb00:7100::'],
            '6to4, every bit set'     => ['2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff', '2002:ffff:ff00::'],
            '6to4, the 40th bit set'  => ['2002:0:100::', '2002:0:100::'],
            '6to4, the 41st bit set'  => ['2002:0:80::', '2002::'],
            'just below 6to4'         => ['2001:cb00:7107:1234::5', '2001:cb00:7107::'],
            'just above 6to4'         => ['2003:cb00:7107:1234::5', '2003:cb00:7107::'],
            '6to4 bytes later on'     => ['2001:2002:7107:1234::5', '2001:2002:7107::'],
            '6to4 byte-swapped'       => ['0220:cb00:7107:1234::5', '220:cb00:7107::'],
        ];
    }

    /**
     * IPv4 truncates to its /24 and IPv6 to its /48, exactly, but for 6to4,
     * whose /40 keeps the /24 of the IPv4 address it embeds.
     *
     * @param  string  $input
     * @param  string  $network
     * @return void
     */
    #[DataProvider('provideNetworks')]
    public function testTheTruncatedNetworkIsExact(string $input, string $network): void
    {
        $minimised = self::minimiser(IpMode::TRUNCATE->value)->minimise($input, null, self::sealer(new RecordingFieldEncrypter), new OmissionLog, self::scope());

        self::assertSame($network, $minimised);
    }

    /**
     * Rows of `[mode, address]`: every invalid address in every mode.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideModesAndInvalidAddresses(): iterable
    {
        foreach (IpMode::cases() as $mode) {
            foreach (self::provideInvalidAddresses() as $label => [$address]) {
                yield $mode->value . ', ' . $label => [$mode->value, $address];
            }
        }
    }

    /**
     * An invalid address is stored in no mode, not even in full, and never
     * reaches the encrypter.
     *
     * @param  string  $mode
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideModesAndInvalidAddresses')]
    public function testAnInvalidAddressIsNullInEveryMode(string $mode, string $address): void
    {
        $encrypter = new RecordingFieldEncrypter;

        self::assertNull(self::minimiser($mode)->minimise($address, self::actor(), self::sealer($encrypter), new OmissionLog, self::scope()));
        self::assertSame([], $encrypter->calls());
    }

    /**
     * An invalid address is diagnosed by its fixed path in every mode, `drop`
     * included, since the mode's choice was never applied to it, and the
     * address itself appears nowhere in the log.
     *
     * @param  string  $mode
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideModesAndInvalidAddresses')]
    public function testAnInvalidAddressIsDiagnosed(string $mode, string $address): void
    {
        $omissions = new OmissionLog;

        self::minimiser($mode)->minimise($address, self::actor(), self::sealer(new RecordingFieldEncrypter), $omissions, self::scope());

        self::assertSame(self::DIAGNOSED, $omissions->toArray());
    }

    /**
     * Rows of `[mode]`: every mode.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideModes(): iterable
    {
        foreach (IpMode::cases() as $mode) {
            yield $mode->value => [$mode->value];
        }
    }

    /**
     * No address is no loss: it is `null` with no diagnostic, and the encrypter
     * is not called.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testNoAddressIsNullWithNoDiagnostic(string $mode): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $omissions = new OmissionLog;

        self::assertNull(self::minimiser($mode)->minimise(null, self::actor(), self::sealer($encrypter), $omissions, self::scope()));
        self::assertNull($omissions->toArray());
        self::assertSame([], $encrypter->calls());
    }

    /**
     * The `drop` mode is configuration rather than loss, so a valid address
     * leaves no diagnostic.
     *
     * @return void
     */
    public function testDropModeAddsNoDiagnostic(): void
    {
        $omissions = new OmissionLog;

        self::assertNull(self::minimiser(IpMode::DROP->value)->minimise('203.0.113.7', self::actor(), self::sealer(new RecordingFieldEncrypter), $omissions, self::scope()));
        self::assertNull($omissions->toArray());
    }

    /**
     * Rows of `[address]`: strings that are not a valid address.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidAddresses(): iterable
    {
        yield from [
            'a word'                => ['not-an-ip'],
            'a byte out of range'   => ['256.1.1.1'],
            'too few bytes'         => ['1.2.3'],
            'a leading zero'        => ['010.0.0.1'],
            'a scope'               => ['fe80::1%eth0'],
            'a leading space'       => [' 203.0.113.7'],
            'empty'                 => [''],
            'a trailing newline'    => ["203.0.113.7\n"],
            'a NUL byte'            => ["203.0.113.7\0"],
            'a port'                => ['203.0.113.7:8080'],
            'brackets'              => ['[2001:db8::1]'],
            'a prefix length'       => ['203.0.113.0/24'],
            'a mapped leading zero' => ['::ffff:010.0.0.1'],
            'too many groups'       => ['1:2:3:4:5:6:7:8:9'],
            'two compressions'      => ['1::2::3'],
            'over-long digits'      => [str_repeat('1', 256)],
            'far over the column'   => [str_repeat('x', 70000)],
            'a control character'   => ["203.0.\x07113.7"],
            'not valid UTF-8'       => ["203.0.113.7\xFF"],
            'a format character'    => ["\u{FEFF}203.0.113.7"],
        ];
    }

    /**
     * Each invalid address is refused with no warning, notice or deprecation,
     * which `inet_pton()` raises when it is given one directly.
     *
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideInvalidAddresses')]
    public function testCanonicalNeverWarnsOnInvalidInput(string $address): void
    {
        $raised = [];

        set_error_handler(static function (int $level, string $message) use (&$raised): bool {
            $raised[] = $message;

            return true;
        });

        try {
            self::assertNull(IpMinimiser::canonical($address));
        } finally {
            restore_error_handler();
        }

        self::assertSame([], $raised);
    }

    /**
     * Rows of `[input, canonical]`: the three forms of an address.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEncryptedForms(): iterable
    {
        yield from [
            'IPv4'   => ['203.0.113.7', '203.0.113.7'],
            'IPv6'   => ['2001:DB8::1', '2001:db8::1'],
            'mapped' => ['::ffff:203.0.113.7', '203.0.113.7'],
        ];
    }

    /**
     * The encrypter seals the canonical address under the actor's key, and what
     * is stored is the envelope's canonical JSON, its keys in bytewise order.
     *
     * @param  string  $input
     * @param  string  $canonical
     * @return void
     */
    #[DataProvider('provideEncryptedForms')]
    public function testTheEncryptModeStoresTheEnvelopesCanonicalJson(string $input, string $canonical): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $omissions = new OmissionLog;
        $actor     = self::actor();

        $stored = self::minimiser(IpMode::ENCRYPT->value)->minimise($input, $actor, self::sealer($encrypter), $omissions, self::scope());

        self::assertSame(sprintf('{"c":"%s","k":"key_42","v":1}', base64_encode('"' . $canonical . '"')), $stored);
        self::assertSame([[$actor, '"' . $canonical . '"']], $encrypter->calls());
        self::assertNull($omissions->toArray());
    }

    /**
     * The address is sealed for the path `["ip"]` of the scope's entry, with
     * the scope's log, tenant, category and owners, so its envelope opens in
     * that column of that entry and nowhere else.
     *
     * @return void
     */
    public function testTheEncryptModeSealsTheAddressAtTheIpPath(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', self::actor(), self::sealer($encrypter), new OmissionLog, self::scope());

        $context = $encrypter->contexts()[0];

        self::assertSame([['ip']], $encrypter->paths());
        self::assertSame(self::ENTRY_ID, $context->entryId);
        self::assertSame('app-eu-1', $context->logId);
        self::assertSame('organisation', $context->tenant?->type);
        self::assertSame('finance', $context->category);
        self::assertSame([self::actor()->id], array_map(static fn (Reference $owner): string => $owner->id, $context->owners));
    }

    /**
     * The address's plaintext is its typed plaintext, the JSON string of its
     * canonical form, which decodes back to the address and to nothing of
     * another type.
     *
     * @return void
     */
    public function testTheAddressPlaintextIsItsJsonString(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        self::minimiser(IpMode::ENCRYPT->value)->minimise('2001:DB8::1', self::actor(), self::sealer($encrypter), new OmissionLog, self::scope());

        $plaintext = $encrypter->calls()[0][1];

        self::assertSame('"2001:db8::1"', $plaintext);
        self::assertSame('2001:db8::1', TypedPlaintext::decode($plaintext));
    }

    /**
     * No mode but `encrypt` asks the encrypter for anything, whatever the
     * scope.
     *
     * @return void
     */
    public function testNoOtherModeSealsTheAddress(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        foreach ([IpMode::FULL, IpMode::TRUNCATE, IpMode::HASH, IpMode::DROP] as $mode) {
            self::minimiser($mode->value)->minimise('203.0.113.7', self::actor(), self::sealer($encrypter), new OmissionLog, self::scope());
        }

        self::assertSame([], $encrypter->calls());
    }

    /**
     * With no actor there is no key to seal under: the address is dropped and
     * diagnosed, and the encrypter is never given it.
     *
     * @return void
     */
    public function testEncryptWithNoActorIsNullAndDiagnosed(): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $omissions = new OmissionLog;

        self::assertNull(self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', null, self::sealer($encrypter), $omissions, self::scope()));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
        self::assertSame([], $encrypter->calls());
    }

    /**
     * An actor with no key drops and diagnoses the address, and reports
     * nothing, because no key is an answer and not a failure.
     *
     * @return void
     */
    public function testEncryptWithNoKeyIsNullAndDiagnosed(): void
    {
        $handler   = new RecordingExceptionHandler;
        $omissions = new OmissionLog;
        $sealer    = new EnvelopeSealer(new NoFieldEncrypter, $handler);

        self::assertNull(self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', self::actor(), $sealer, $omissions, self::scope()));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
        self::assertSame([], $handler->reports());
    }

    /**
     * A throwing encrypter costs the address and never the record, and its
     * failure is reported once.
     *
     * @return void
     */
    public function testEncryptWithAThrowingEncrypterIsNullAndDiagnosed(): void
    {
        $handler   = new RecordingExceptionHandler;
        $omissions = new OmissionLog;
        $sealer    = new EnvelopeSealer(new ThrowingFieldEncrypter, $handler);

        self::assertNull(self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', self::actor(), $sealer, $omissions, self::scope()));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
        self::assertCount(1, $handler->reports());
    }

    /**
     * A malformed envelope costs the address too, and is reported once.
     *
     * @return void
     */
    public function testEncryptWithAMalformedEnvelopeIsNullAndDiagnosed(): void
    {
        $handler   = new RecordingExceptionHandler;
        $omissions = new OmissionLog;
        $sealer    = new EnvelopeSealer(new MalformedFieldEncrypter(['v' => 1, 'k' => 'k']), $handler);

        self::assertNull(self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', self::actor(), $sealer, $omissions, self::scope()));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
        self::assertCount(1, $handler->reports());
    }

    /**
     * An encrypter that already failed during this capture is not called again
     * for the address, which is dropped and diagnosed like any other failure.
     *
     * @return void
     */
    public function testEncryptAfterAnEarlierFailureIsNullAndDiagnosed(): void
    {
        $encrypter = new ThrowingFieldEncrypter;
        $handler   = new RecordingExceptionHandler;
        $omissions = new OmissionLog;
        $sealer    = new EnvelopeSealer($encrypter, $handler);

        $sealer->seal(self::actor(), '"an earlier field"', self::scope()->at(['properties', 'field']));

        self::assertNull(self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', self::actor(), $sealer, $omissions, self::scope()));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
        self::assertSame(1, $encrypter->calls());
        self::assertCount(1, $handler->reports());
    }

    /**
     * An envelope of exactly the column's 255 bytes is stored whole.
     *
     * @return void
     */
    public function testAnEnvelopeOf255BytesFits(): void
    {
        $omissions = new OmissionLog;
        $stored    = self::encryptedUnder(str_repeat('a', IpMinimiser::COLUMN_BYTES - self::ENVELOPE_FRAME_BYTES), $omissions);

        self::assertSame(255, IpMinimiser::COLUMN_BYTES);
        self::assertSame('{"c":"' . str_repeat('a', 233) . '","k":"k","v":1}', $stored);
        self::assertSame(255, strlen($stored));
        self::assertNull($omissions->toArray());
    }

    /**
     * One byte more and the address is dropped and diagnosed: a cut envelope
     * could not be decrypted, so it is never truncated.
     *
     * @return void
     */
    public function testAnEnvelopeOf256BytesIsDroppedAndNeverTruncated(): void
    {
        $omissions = new OmissionLog;

        self::assertNull(self::encryptedUnder(str_repeat('a', 234), $omissions));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
    }

    /**
     * The limit is on encoded bytes: 117 two-byte characters are far fewer than
     * 255 characters and one byte too many; protects against a mutation that
     * counts characters.
     *
     * @return void
     */
    public function testTheColumnLimitCountsBytesNotCharacters(): void
    {
        $omissions = new OmissionLog;

        self::assertNull(self::encryptedUnder(str_repeat('é', 117), $omissions));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());
    }

    /**
     * The limit is on what is stored, after escaping: quotes that fit raw and
     * not once escaped are dropped, and slashes, which the canonical encoding
     * does not escape, still fit.
     *
     * @return void
     */
    public function testTheColumnLimitCountsTheEncodedForm(): void
    {
        $omissions = new OmissionLog;

        self::assertNull(self::encryptedUnder(str_repeat('"', 117), $omissions));
        self::assertSame(self::DIAGNOSED, $omissions->toArray());

        $omissions = new OmissionLog;
        $slashes   = str_repeat('/', 233);

        self::assertSame('{"c":"' . $slashes . '","k":"k","v":1}', self::encryptedUnder($slashes, $omissions));
        self::assertNull($omissions->toArray());
    }

    /**
     * A mode the setting does not allow fails even a record with no address, so
     * it can never go unnoticed until one arrives.
     *
     * @return void
     */
    public function testAMalformedModeFailsWithNoAddress(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.');

        self::minimiser('partial')->minimise(null, null, self::sealer(new RecordingFieldEncrypter), new OmissionLog, self::scope());
    }

    /**
     * Each record reads the mode again, so nothing of a former mode is kept.
     *
     * @return void
     */
    public function testTheModeIsReadOnEveryCall(): void
    {
        $config    = new Repository(['audit-log' => ['redaction' => ['ip' => IpMode::FULL->value, 'key' => self::ROOT_KEY]]]);
        $settings  = new RedactionSettings($config);
        $minimiser = new IpMinimiser($settings, new IdentifierHasher($settings));
        $sealer    = self::sealer(new RecordingFieldEncrypter);

        self::assertSame('203.0.113.7', $minimiser->minimise('203.0.113.7', null, $sealer, new OmissionLog, self::scope()));

        $config->set('audit-log.redaction.ip', IpMode::TRUNCATE->value);

        self::assertSame('203.0.113.0', $minimiser->minimise('203.0.113.7', null, $sealer, new OmissionLog, self::scope()));
    }

    /**
     * An address is hashed in its own domain, so its hash never equals the hash
     * of the same text as an identifier or as a field, and carries a different
     * fingerprint.
     *
     * @return void
     */
    public function testAnIpHashIsNeverAnIdentifierHash(): void
    {
        $hasher = new IdentifierHasher(self::settings(IpMode::HASH->value));
        $stored = (string) self::minimiser(IpMode::HASH->value)->minimise('203.0.113.7', null, self::sealer(new RecordingFieldEncrypter), new OmissionLog, self::scope());

        $identifier = (string) $hasher->identifier('203.0.113.7');
        $field      = $hasher->field('203.0.113.7');

        self::assertNotSame($identifier, $stored);
        self::assertNotSame($field, $stored);
        self::assertNotSame(substr($identifier, 0, 16), substr($stored, 0, 16));
        self::assertNotSame(substr($field, 0, 16), substr($stored, 0, 16));
    }

    /**
     * Rows of `[method, parameter]`: every parameter holding an address, the
     * private helpers included.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAddressParameters(): iterable
    {
        yield from [
            'minimise'  => ['minimise', 'ip'],
            'canonical' => ['canonical', 'ip'],
            'truncated' => ['truncated', 'canonicalIp'],
            'encrypted' => ['encrypted', 'canonicalIp'],
        ];
    }

    /**
     * Every parameter that holds an address is marked sensitive.
     *
     * @param  string  $method
     * @param  string  $parameter
     * @return void
     *
     * @throws \ReflectionException
     */
    #[DataProvider('provideAddressParameters')]
    public function testTheAddressParameterIsSensitive(string $method, string $parameter): void
    {
        self::assertCount(1, (new \ReflectionParameter([IpMinimiser::class, $method], $parameter))->getAttributes(\SensitiveParameter::class));
    }

    /**
     * With arguments kept in stack traces, a failure while hashing holds
     * neither the address nor the key.
     *
     * @return void
     */
    public function testNoFrameOfAFailureHoldsTheAddress(): void
    {
        $settings  = new RedactionSettings(new Repository(['audit-log' => ['redaction' => ['ip' => IpMode::HASH->value, 'key' => 'too-short']]]));
        $minimiser = new IpMinimiser($settings, new IdentifierHasher($settings));
        $ignored   = ini_set('zend.exception_ignore_args', '0');

        try {
            $minimiser->minimise('203.0.113.7', null, self::sealer(new RecordingFieldEncrypter), new OmissionLog, self::scope());
            self::fail('Expected the key to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString('203.0.113.7', $exception->getMessage());
            self::assertStringNotContainsString('203.0.113.7', print_r($exception->getTrace(), true));
            self::assertStringNotContainsString('too-short', print_r($exception->getTrace(), true));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }
    }

    /**
     * What the encrypt mode stores of an envelope with the ciphertext, the key
     * `k` and version 1.
     *
     * @param  string  $ciphertext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return ?string
     */
    private static function encryptedUnder(string $ciphertext, OmissionLog $omissions): ?string
    {
        $encrypter = new MalformedFieldEncrypter(['c' => $ciphertext, 'k' => 'k', 'v' => 1]);

        return self::minimiser(IpMode::ENCRYPT->value)->minimise('203.0.113.7', self::actor(), self::sealer($encrypter), $omissions, self::scope());
    }

    /**
     * A minimiser of the mode, under the root key of the golden hashes.
     *
     * @param  string  $mode
     * @return \SineMacula\Laravel\AuditLog\Privacy\IpMinimiser
     */
    private static function minimiser(string $mode): IpMinimiser
    {
        $settings = self::settings($mode);

        return new IpMinimiser($settings, new IdentifierHasher($settings));
    }

    /**
     * The settings of the mode, under the root key of the golden hashes.
     *
     * @param  string  $mode
     * @return \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings
     */
    private static function settings(string $mode): RedactionSettings
    {
        return new RedactionSettings(new Repository(['audit-log' => ['redaction' => ['ip' => $mode, 'key' => self::ROOT_KEY]]]));
    }

    /**
     * A sealer over the encrypter.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer
     */
    private static function sealer(FieldEncrypter $encrypter): EnvelopeSealer
    {
        return new EnvelopeSealer($encrypter, new RecordingExceptionHandler);
    }

    /**
     * The scope every address is sealed in: an entry of an organisation's,
     * encrypting for the actor.
     *
     * @return \SineMacula\Laravel\AuditLog\Privacy\SealingScope
     */
    private static function scope(): SealingScope
    {
        return new SealingScope(self::ENTRY_ID, 'app-eu-1', Reference::of('organisation', 'org_01'), 'finance', [self::actor()]);
    }

    /**
     * The actor an address is sealed under.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function actor(): Reference
    {
        return Reference::of('user', 42);
    }
}
