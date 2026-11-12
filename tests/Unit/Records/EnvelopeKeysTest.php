<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * Unit tests for the keys a record's envelopes name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnvelopeKeys::class)]
final class EnvelopeKeysTest extends TestCase
{
    /** @var string A key. */
    private const string FIRST = '01932b4e-9000-7000-8000-000000000001';

    /** @var string Another key, sorting after the first. */
    private const string SECOND = '01932b4e-9000-7000-8000-000000000002';

    /** @var string A third key, sorting after the second. */
    private const string THIRD = '01932b4e-9000-7000-8000-00000000000a';

    /** @var string A ciphertext, as the reader requires it: non-empty clean text. */
    private const string CIPHERTEXT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    /**
     * An envelope is found at any depth of the properties and the context, as
     * an array or an object, and nothing inside one is read.
     *
     * @return void
     */
    public function testItFindsEveryEnvelopeAtAnyDepth(): void
    {
        $deep = (object) ['a' => [(object) ['b' => ['c' => [self::envelope(self::THIRD)]]]]];

        $properties = [
            'card'   => self::envelope(self::FIRST),
            'nested' => $deep,
            'list'   => ['plain', 7, null, true],
        ];

        $context = (object) ['session' => (object) self::envelope(self::SECOND)];

        self::assertSame([self::FIRST, self::SECOND, self::THIRD], EnvelopeKeys::of($properties, $context, null));
        self::assertSame([self::FIRST], EnvelopeKeys::of(self::envelope(self::FIRST), null, null));
        self::assertSame([self::SECOND], EnvelopeKeys::of(null, [[self::envelope(self::SECOND)]], null));
        self::assertSame([], EnvelopeKeys::of(null, null, null));
        self::assertSame([], EnvelopeKeys::of('plain', 42, '203.0.113.7'));
    }

    /**
     * An IP address stored as an envelope is found, and any other IP address is
     * not.
     *
     * @return void
     */
    public function testAnIpEnvelopeIsFound(): void
    {
        $ip = json_encode(self::envelope(self::FIRST), JSON_THROW_ON_ERROR);

        self::assertSame([self::FIRST], EnvelopeKeys::of(null, null, $ip));
        self::assertSame([self::FIRST, self::SECOND], EnvelopeKeys::of(['a' => self::envelope(self::SECOND)], null, $ip));

        foreach (
            [
                '203.0.113.7',
                '2001:db8::1',
                '{not json',
                '{"v":1,"k":"' . self::FIRST . '","c":{"nested":true}}',
                '{"v":1,"k":"' . self::FIRST . '"}',
                ' {"v":1,"k":"' . self::FIRST . '","c":"x"}',
                '{"v":1,"k":"key-1","c":"x"}',
                '[1,2,3]',
            ] as $other
        ) {
            self::assertSame([], EnvelopeKeys::of(null, null, $other), $other);
        }
    }

    /**
     * Rows of `[value, whether the read path reads it as an envelope]`: each
     * way a value can be or fail to be exactly an envelope.
     *
     * @return iterable<string, array{0: array<array-key, bool|float|int|string|null>, 1: bool}>
     */
    public static function provideCandidates(): iterable
    {
        yield from [
            'an envelope'                      => [['v' => 1, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], true],
            'its members in another order'     => [['c' => self::CIPHERTEXT, 'k' => self::FIRST, 'v' => 1], true],
            'a later version'                  => [['v' => 2, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], true],
            'the largest exact version'        => [['v' => ValueNormaliser::MAX_SAFE_INTEGER, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], true],
            'a version past the exact range'   => [['v' => ValueNormaliser::MAX_SAFE_INTEGER + 1, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], false],
            'a version of 0'                   => [['v' => 0, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], false],
            'a negative version'               => [['v' => -1, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], false],
            'a version as a string'            => [['v' => '1', 'k' => self::FIRST, 'c' => self::CIPHERTEXT], false],
            'a version as a float'             => [['v' => 1.0, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], false],
            'a version that is true'           => [['v' => true, 'k' => self::FIRST, 'c' => self::CIPHERTEXT], false],
            'an empty ciphertext'              => [['v' => 1, 'k' => self::FIRST, 'c' => ''], false],
            'a ciphertext with a control byte' => [['v' => 1, 'k' => self::FIRST, 'c' => "AAAA\0"], false],
            'a ciphertext that is a number'    => [['v' => 1, 'k' => self::FIRST, 'c' => 7], false],
            'a key that is null'               => [['v' => 1, 'k' => null, 'c' => self::CIPHERTEXT], false],
            'a member too many'                => [['v' => 1, 'k' => self::FIRST, 'c' => self::CIPHERTEXT, 'd' => 'x'], false],
            'a member missing'                 => [['v' => 1, 'k' => self::FIRST], false],
            'members in upper case'            => [['V' => 1, 'K' => self::FIRST, 'C' => self::CIPHERTEXT], false],
            'a list of three'                  => [[1, self::FIRST, self::CIPHERTEXT], false],
        ];
    }

    /**
     * A value names a key exactly when the read path builds an encrypted field
     * from it.
     *
     * @param  array<array-key, bool|float|int|string|null>  $candidate
     * @param  bool  $envelope
     * @return void
     */
    #[DataProvider('provideCandidates')]
    public function testItFindsExactlyWhatTheProjectorReadsAsAnEnvelope(array $candidate, bool $envelope): void
    {
        self::assertSame($envelope, self::readsAsAnEnvelope($candidate), 'The read path disagrees with the row.');
        self::assertSame($envelope ? [self::FIRST] : [], EnvelopeKeys::of(['field' => $candidate], null, null));
        self::assertSame($envelope ? [self::FIRST] : [], EnvelopeKeys::of(null, ['field' => (object) $candidate], null));
    }

    /**
     * Each key is named once however many envelopes name it, and the keys are
     * sorted bytewise, digits before letters.
     *
     * @return void
     */
    public function testTheKeysAreDistinctAndSorted(): void
    {
        $properties = [
            'z' => self::envelope(self::THIRD),
            'y' => self::envelope(self::FIRST),
            'x' => [self::envelope(self::SECOND), self::envelope(self::FIRST)],
        ];

        $ip = json_encode(self::envelope(self::SECOND), JSON_THROW_ON_ERROR);

        self::assertSame([self::FIRST, self::SECOND, self::THIRD], EnvelopeKeys::of($properties, ['again' => self::envelope(self::THIRD)], $ip));
    }

    /**
     * A key that is not a canonical lower-case UUID names no key use, though
     * the reader would show its envelope.
     *
     * @return void
     */
    public function testAKeyThatIsNoUuidIsLeftOut(): void
    {
        $properties = [
            'custom' => self::envelope('vault:transit/users/42'),
            'upper'  => self::envelope(strtoupper(self::FIRST)),
            'braced' => self::envelope('{' . self::FIRST . '}'),
            'kept'   => self::envelope(self::SECOND),
        ];

        self::assertSame([self::SECOND], EnvelopeKeys::of($properties, null, null));
    }

    /**
     * A value the application shaped as an envelope is read as one, and its key
     * is found like any other.
     *
     * @return void
     */
    public function testAnApplicationShapedEnvelopeIsFound(): void
    {
        $retained = ['payload' => ['c' => 'application text', 'k' => self::THIRD, 'v' => 1]];

        self::assertTrue(self::readsAsAnEnvelope($retained['payload']));
        self::assertSame([self::THIRD], EnvelopeKeys::of($retained, null, null));
    }

    /**
     * A record's keys are those of its properties, its context and its IP
     * address.
     *
     * @return void
     */
    public function testARecordsKeysAreThoseOfItsColumns(): void
    {
        $record = AuditRecord::fromEnvelope([
            ...self::fields(),
            'ip'         => json_encode(self::envelope(self::THIRD), JSON_THROW_ON_ERROR),
            'context'    => ['session' => self::envelope(self::SECOND)],
            'properties' => ['card' => self::envelope(self::FIRST), 'note' => 'plain'],
        ]);

        self::assertSame([self::FIRST, self::SECOND, self::THIRD], EnvelopeKeys::ofRecord($record));
        self::assertSame([], EnvelopeKeys::ofRecord(AuditRecord::fromEnvelope(self::fields())));
    }

    /**
     * The constructor is private: the class is a utility container only.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(EnvelopeKeys::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(EnvelopeKeys::class, $instance);
    }

    /**
     * An envelope naming the key.
     *
     * @param  string  $key
     * @return array{v: int, k: string, c: string}
     */
    private static function envelope(string $key): array
    {
        return ['v' => 1, 'k' => $key, 'c' => self::CIPHERTEXT];
    }

    /**
     * Whether the read path builds an encrypted field from the value, asked of
     * the factory it builds every field with.
     *
     * @param  array<array-key, bool|float|int|string|null>  $candidate
     * @return bool
     */
    private static function readsAsAnEnvelope(array $candidate): bool
    {
        return EncryptedField::fromEnvelope(self::FIRST, ['properties', 'field'], $candidate) !== null;
    }

    /**
     * The fields of a minimal record, with no envelope.
     *
     * @return array<string, array<string, string>|int|string|null>
     */
    private static function fields(): array
    {
        return [
            'id'               => self::FIRST,
            'record_version'   => 1,
            'event'            => 'invoice.approved',
            'event_version'    => 1,
            'category'         => 'default',
            'outcome'          => 'success',
            'reason'           => null,
            'actor_type'       => null,
            'actor_id'         => null,
            'subject_type'     => null,
            'subject_id'       => null,
            'principal_type'   => null,
            'principal_id'     => null,
            'tenant_type'      => null,
            'tenant_id'        => null,
            'credential_id'    => null,
            'guard'            => null,
            'session_id'       => null,
            'request_id'       => null,
            'trace_id'         => null,
            'correlation_id'   => null,
            'origin'           => 'console',
            'provenance'       => 'captured',
            'source_id'        => 'app',
            'source_region'    => null,
            'source_record_id' => null,
            'import_batch_id'  => null,
            'source_digest'    => null,
            'ip'               => null,
            'user_agent'       => null,
            'context'          => null,
            'properties'       => null,
            'occurred_at'      => '2026-11-01T12:00:00.000000Z',
        ];
    }
}
