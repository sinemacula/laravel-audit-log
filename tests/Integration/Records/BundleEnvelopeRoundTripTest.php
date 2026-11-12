<?php

declare(strict_types = 1);

namespace Tests\Integration\Records;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Encryption\StringEncrypter;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for bundles through the outbox's `payload` column; covers
 * nothing, as its slowness would get covered mutants skipped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class BundleEnvelopeRoundTripTest extends TestCase
{
    use InteractsWithOutbox, SeedsTheOutbox;

    /** @var string The memory limit the tests run under. */
    private const string MEMORY_LIMIT = '1G';

    /** @var int The greatest `audit-log.capture.bulk.max_bytes` takes: 8 MiB of canonical form. */
    private const int BULK_MAX_BYTES = 8388608;

    /** @var int The greatest `audit-log.capture.bulk.max_members` takes. */
    private const int BULK_MAX_MEMBERS = 1000000;

    /** @var int What 8 MiB of canonical form is sealed within: 15 MiB, inside the envelope's bound. */
    private const int SEALED_MAX_BYTES = 15728640;

    /** @var int What MySQL's `max_allowed_packet` defaults to: 64 MiB. */
    private const int DEFAULT_PACKET_BYTES = 67108864;

    /** @var string The type of every member of the largest manifest. */
    private const string MEMBER_TYPE = 'invoice';

    /** @var string The memory limit before the test. */
    private string $memoryLimit = '';

    /**
     * Raise the memory limit.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->memoryLimit = ini_get('memory_limit');

        ini_set('memory_limit', self::MEMORY_LIMIT);
    }

    /**
     * Restore the memory limit, never below what is held: PHP refuses that.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        gc_mem_caches();

        $limit = ini_parse_quantity($this->memoryLimit);

        ini_set('memory_limit', $limit < 0 ? $this->memoryLimit : (string) max($limit, memory_get_usage(true)));
    }

    /**
     * A bundle encrypted into `payload` reads back and decodes byte for byte.
     *
     * @return void
     */
    public function testABundleSurvivesTheOutboxColumn(): void
    {
        $record   = $this->finalisedRecord(RecordFactory::bundled());
        $envelope = app(EnvelopeCodec::class)->encode($record);
        $payload  = $this->encryptedEnvelope($record);

        self::assertSame(['attachment', 'bundle_version', 'record'], array_keys((array) json_decode($envelope, true, 513, JSON_THROW_ON_ERROR)));

        $this->seedOutboxRow($record->record->id, $payload);

        self::assertSame(1, $this->outboxCount());

        $read = $this->payloadOf($record->record->id);

        self::assertSame($payload, $read);
        self::assertSame($envelope, app(StringEncrypter::class)->decryptString($read));

        $decoded = app(EnvelopeCodec::class)->decode(app(StringEncrypter::class)->decryptString($read), $record->record->id);

        self::assertSame($envelope, app(EnvelopeCodec::class)->encode($decoded));
        self::assertSame($record->hmac, $decoded->hmac);
        self::assertEquals($record->record->attachment, $decoded->record->attachment);

        $attachment = $decoded->record->attachment;

        self::assertNotNull($attachment);
        self::assertSame(['count' => 3, 'digest' => $attachment->digest], Manifest::readCanonical(app(StringEncrypter::class)->decryptString((string) $attachment->members)));
        self::assertSame(
            ['artifact_id' => $attachment->id, 'count' => 3, 'digest' => $attachment->digest, 'kind' => 'bulk'],
            $decoded->record->properties['_audit']['manifest'] ?? null,
        );
    }

    /**
     * The largest bundle seals within 15 MiB and, encrypted, fits the column
     * and MySQL's default packet.
     *
     * @return void
     */
    public function testTheLargestBundleFitsTheColumnAndThePacket(): void
    {
        $manifest = $this->largestManifest();

        self::assertSame(self::BULK_MAX_BYTES, strlen($manifest->canonical));

        $record   = $this->bundleAtTheBound($manifest);
        $envelope = app(EnvelopeCodec::class)->encode($record);

        self::assertNotNull($record->record->attachment);
        self::assertSame(EnvelopeCodec::MAX_BYTES, strlen($envelope));
        self::assertLessThan(self::SEALED_MAX_BYTES, strlen((string) $record->record->attachment->members));

        $payload = app(StringEncrypter::class)->encryptString($envelope);

        self::assertLessThan(self::DEFAULT_PACKET_BYTES, strlen($payload) + 1024);

        $this->assertThePacketTakes(strlen($payload));

        app(Outbox::class)->insert($record->record->id, $payload);

        $read = $this->payloadOf($record->record->id);

        self::assertSame(strlen($payload), strlen($read));
        self::assertSame(hash('sha256', $payload), hash('sha256', $read));

        unset($payload);

        $decoded = app(EnvelopeCodec::class)->decode(app(StringEncrypter::class)->decryptString($read), $record->record->id);

        unset($read);

        self::assertSame(hash('sha256', $envelope), hash('sha256', app(EnvelopeCodec::class)->encode($decoded)));
        self::assertNotNull($decoded->record->attachment);
        self::assertSame($manifest->digest, $decoded->record->attachment->digest);
        self::assertSame($manifest->count, $decoded->record->attachment->memberCount);
        self::assertSame(hash('sha256', $manifest->canonical), hash('sha256', app(StringEncrypter::class)->decryptString((string) $decoded->record->attachment->members)));
    }

    /**
     * The manifest at the greatest canonical size the settings allow.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     */
    private function largestManifest(): Manifest
    {
        $config = app(ConfigRepository::class);

        $config->set(['audit-log.capture.bulk.max_bytes' => self::BULK_MAX_BYTES, 'audit-log.capture.bulk.max_members' => self::BULK_MAX_MEMBERS]);

        $settings = app(CaptureSettings::class);
        $manifest = Manifest::of(self::membersOfBytes(self::BULK_MAX_BYTES), $settings->bulkMaxMembers(), $settings->bulkMaxBytes());

        $config->set('audit-log.capture.bulk.max_bytes', self::BULK_MAX_BYTES + 1);

        try {
            $settings->bulkMaxBytes();

            self::fail('Expected the settings to take no larger manifest.');
        } catch (\InvalidArgumentException) {
            // The greatest manifest is the one built above
        }

        return $manifest;
    }

    /**
     * References whose manifest's canonical form is exactly the bytes given; a
     * pair is its id's length plus 14 bytes and a comma.
     *
     * @param  int  $bytes
     * @return \Generator<int, \SineMacula\Laravel\AuditLog\Records\Reference, void, void>
     */
    private static function membersOfBytes(int $bytes): \Generator
    {
        $longest = Reference::MAX_CHARACTERS;
        $full    = intdiv($bytes - 1, $longest + 15) - 1;
        $rest    = $bytes                            - 1 - ($full * ($longest + 15)) - 30;
        $first   = min($longest, $rest - 1);

        for ($index = 0; $index < $full; $index++) {
            yield Reference::of(self::MEMBER_TYPE, str_pad(sprintf('%07d', $index), $longest, 'x'));
        }

        yield Reference::of(self::MEMBER_TYPE, str_repeat('y', $first));
        yield Reference::of(self::MEMBER_TYPE, str_repeat('z', $rest - $first));
    }

    /**
     * The bulk record of the manifest, padded to exactly the envelope's bound.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function bundleAtTheBound(Manifest $manifest): FinalisedRecord
    {
        $attachment = Attachment::sealed($manifest, app(StringEncrypter::class));
        $base       = RecordFactory::bundled();
        $unpadded   = app(EnvelopeCodec::class)->encode($this->finalisedRecord(self::padded($base, $manifest, $attachment, 0)));

        return $this->finalisedRecord(self::padded($base, $manifest, $attachment, EnvelopeCodec::MAX_BYTES - strlen($unpadded)));
    }

    /**
     * The bulk record with the manifest's descriptor and attachment, padded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $base
     * @param  \SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @param  \SineMacula\Laravel\AuditLog\Records\Attachment  $attachment
     * @param  int  $length
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function padded(AuditRecord $base, Manifest $manifest, Attachment $attachment, int $length): AuditRecord
    {
        $properties = ['batch' => 'march', 'pad' => str_repeat('a', $length), '_audit' => ['manifest' => $manifest->descriptor()]];

        return RecordFactory::withFields(['properties' => $properties, 'attachment' => $attachment], $base);
    }

    /**
     * On MySQL, assert the server takes a payload of the length.
     *
     * @param  int  $length
     * @return void
     */
    private function assertThePacketTakes(int $length): void
    {
        $connection = $this->outboxConnection();

        if ($connection->getDriverName() !== 'mysql') {
            return;
        }

        $packet = $connection->scalar('select @@global.max_allowed_packet');

        self::assertIsNumeric($packet);
        self::assertGreaterThan($length, (int) $packet);
    }

    /**
     * The encrypted payload the outbox holds under the id.
     *
     * @param  string  $id
     * @return string
     */
    private function payloadOf(string $id): string
    {
        $payload = $this->outboxConnection()->table(DeliveryTables::outboxTable())->where('id', $id)->value('payload');

        self::assertIsString($payload);

        return $payload;
    }
}
