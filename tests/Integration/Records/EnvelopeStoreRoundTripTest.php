<?php

declare(strict_types = 1);

namespace Tests\Integration\Records;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;
use Tests\Unit\Records\EnvelopeCodecTest;

/**
 * Integration tests for storing a record rebuilt from its envelope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnvelopeCodec::class)]
#[CoversClass(FinalisedRecord::class)]
#[CoversClass(RowCodec::class)]
final class EnvelopeStoreRoundTripTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string When the record is finalised: after the activity occurred. */
    private const string RECORDED_AT = '2026-11-01T12:00:01.654321Z';

    /** @var string The signing key's id. */
    private const string KEY_ID = 'k2026';

    /** @var string The signing key's secret, as its own 32 bytes. */
    private const string KEY_SECRET = 'envelope-store current secret 32';

    /** @var string An HMAC that stands in until the envelope is signed. */
    private const string PLACEHOLDER_HMAC = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * A decoded record's row reads back with the envelope's canonical bytes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProviderExternal(EnvelopeCodecTest::class, 'provideVectors')]
    public function testADecodedRecordStoresARowEqualToTheEnvelope(array $fields): void
    {
        $envelope = self::envelope($fields);

        $this->store()->store($this->codec()->decode($envelope));

        $stored   = $this->storedRow(self::ID);
        $expected = json_decode($envelope, false, 513, JSON_THROW_ON_ERROR);

        self::assertInstanceOf(\stdClass::class, $expected);
        self::assertSame($envelope, CanonicalEncoder::encode($stored));
        self::assertSame(get_debug_type($expected->context), get_debug_type($stored['context']));
        self::assertSame(get_debug_type($expected->properties), get_debug_type($stored['properties']));
    }

    /**
     * The row a decoded record stores verifies as the engine returns it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $fields
     * @return void
     */
    #[DataProviderExternal(EnvelopeCodecTest::class, 'provideVectors')]
    public function testTheStoredRowVerifies(array $fields): void
    {
        $this->store()->store($this->codec()->decode(self::envelope($fields)));

        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow(self::ID)));
    }

    /**
     * A decoded record is a duplicate of itself and of its source record.
     *
     * @return void
     */
    public function testADecodedRecordResolvesAsADuplicateOfItself(): void
    {
        $codec   = $this->codec();
        $decoded = $codec->decode(self::envelope(['context' => new \stdClass, 'properties' => (object) ['0' => 'a', '1' => (object) []]]));

        $this->store()->store($decoded);
        $this->store()->store($decoded);
        $this->store()->store($codec->decode($codec->encode($decoded)));

        self::assertSame(1, $this->entryCount());

        $id        = '01932b4e-8a40-7000-8000-000000000002';
        $finalised = $this->finaliser()->finalise(RecordFactory::captured(['lines' => [], 'n' => [1 => 'x', 0 => 'y']], $id));

        $this->store()->store($finalised);
        $this->store()->store($codec->decode($codec->encode($finalised)));

        self::assertSame(2, $this->entryCount());
        self::assertSame($finalised->hmac, $this->storedRow($id)['hmac']);
    }

    /**
     * A map with sequential numeric keys stays a map through the engine's JSON.
     *
     * @return void
     */
    public function testAMapWithSequentialNumericKeysSurvivesTheEngine(): void
    {
        $properties = (object) ['0' => 'a', '1' => 'b', '2' => (object) ['0' => 'c'], '3' => [(object) ['0' => 'd']]];

        $this->store()->store($this->codec()->decode(self::envelope(['context' => (object) ['0' => 'z'], 'properties' => $properties])));

        $stored = $this->storedRow(self::ID);

        self::assertInstanceOf(\stdClass::class, $stored['properties']);
        self::assertInstanceOf(\stdClass::class, $stored['context']);
        self::assertSame('{"0":"a","1":"b","2":{"0":"c"},"3":[{"0":"d"}]}', CanonicalEncoder::encode($stored['properties']));
        self::assertSame('{"0":"z"}', CanonicalEncoder::encode($stored['context']));
        self::assertTrue(app(RecordSigner::class)->verifies($stored));
    }

    /**
     * Sign with an explicit ring, so tests can sign with the key's secret.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app(ConfigRepository::class)->set('audit-log.integrity', ['keys' => [self::KEY_ID => self::KEY_SECRET], 'current' => self::KEY_ID]);
    }

    /**
     * The codec over the package's signer.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\EnvelopeCodec
     */
    private function codec(): EnvelopeCodec
    {
        return new EnvelopeCodec(app(RecordSigner::class));
    }

    /**
     * The envelope of a record finalised under `k2026` with the fields given,
     * signed as the signer signs.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return string
     */
    private static function envelope(array $fields): string
    {
        $finalised = new FinalisedRecord(RecordFactory::captured(id: self::ID), self::RECORDED_AT, 1, self::KEY_ID, self::PLACEHOLDER_HMAC);
        $columns   = array_replace($finalised->toArray(), $fields);
        $signed    = array_intersect_key($columns, array_flip(RecordSigner::SIGNED_COLUMNS));

        $columns['hmac'] = hash_hmac('sha256', CanonicalEncoder::encode($signed), self::KEY_SECRET);

        return CanonicalEncoder::encode($columns);
    }
}
