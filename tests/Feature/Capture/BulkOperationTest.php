<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Capture\Models\Tag;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for a bulk operation through the facade and the database store:
 * a thousand subjects written as one entry and one artifact listing each of
 * them once, whose decrypted members hash to the digest the entry signs; a
 * stack with a destination that keeps no attachments refusing the operation up
 * front; a manifest over either bound refused, never truncated, with nothing
 * written; and a sealed bulk entry verifying.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(DatabaseAuditStore::class)]
final class BulkOperationTest extends TestCase
{
    use TampersWithTheLog;

    /** @var string The code every bulk operation records. */
    private const string CODE = 'tag.archived';

    /** @var int How many tags a bulk operation names. */
    private const int SUBJECTS = 1000;

    /** @var string When a bulk operation is recorded, unless a test says otherwise. */
    private const string RECORDED_AT = '2026-11-01 12:00:00';

    /** @var string When the log is sealed: after every bulk operation is recorded. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When the log is verified: past the anchoring grace of every seal. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /**
     * Create the tags' table and a thousand tags in it, written without a model
     * event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createTagsTable();

        foreach (array_chunk(range(1, self::SUBJECTS), 250) as $chunk) {
            Tag::query()->insert(array_map(static fn (int $index): array => ['name' => 'tag-' . $index], $chunk));
        }
    }

    /**
     * A thousand subjects, some given twice, are one entry and one artifact of
     * a thousand members: each tag once, in canonical order, whose canonical
     * form, decrypted, hashes to the digest the entry and the artifact both
     * hold.
     *
     * @return void
     */
    public function testAThousandSubjectsGiveOneEntryAndOneManifestOfAThousandMembers(): void
    {
        $tags = Tag::query()->orderBy('id')->get();

        $record = AuditLog::bulk(self::CODE, [...$tags->all(), ...$tags->take(10)->all()])->record();

        self::assertSame(1, self::entries()->count());
        self::assertSame(1, self::artifacts()->count());

        $artifact   = (array) self::artifacts()->first();
        $descriptor = $record->properties['_audit']['manifest'] ?? null;
        $canonical  = app(StringEncrypter::class)->decryptString((string) $artifact['members']);
        $members    = $tags->map(static fn (Tag $tag): array => [Tag::class, (string) $tag->id])->all();

        usort($members, static fn (array $a, array $b): int => strcmp($a[1], $b[1]));

        self::assertSame([$record->id, 'bulk', self::SUBJECTS], [$artifact['entry_id'], $artifact['kind'], (int) $artifact['member_count']]);
        self::assertSame(['artifact_id' => $artifact['id'], 'digest' => hash('sha256', $canonical), 'count' => self::SUBJECTS], $descriptor);
        self::assertSame($artifact['digest'], hash('sha256', $canonical));
        self::assertSame(Manifest::encode($members), $canonical);
        self::assertSame($descriptor, self::storedProperties()['_audit']['manifest'] ?? null);
    }

    /**
     * The descriptor is signed with the entry: the stored row verifies, and the
     * same row with another digest, count or artifact id does not.
     *
     * @return void
     */
    public function testTheDescriptorIsSigned(): void
    {
        AuditLog::bulk(self::CODE, Tag::query()->get())->record();

        $row    = (new RowCodec)->decode((array) self::entries()->first());
        $signer = app(RecordSigner::class);

        self::assertTrue($signer->verifies($row));

        foreach (['digest' => str_repeat('0', 64), 'count' => self::SUBJECTS - 1, 'artifact_id' => '01932b4e-9000-7000-8000-00000000ffff'] as $field => $value) {
            $properties = json_decode(json_encode($row['properties'], JSON_THROW_ON_ERROR), false, 16, JSON_THROW_ON_ERROR);

            self::assertInstanceOf(\stdClass::class, $properties);

            $properties->_audit->manifest->{$field} = $value;

            self::assertFalse($signer->verifies([...$row, 'properties' => $properties]), "A changed {$field} still verifies.");
        }
    }

    /**
     * A stack with a destination that keeps no attachments refuses a bulk
     * operation before reading a subject, naming the stack, and nothing is
     * written.
     *
     * @return void
     */
    public function testAStackWithALogDestinationRefusesBulk(): void
    {
        $this->app?->instance(AuditStore::class, new StackAuditStore([
            'database' => app(DatabaseAuditStore::class),
            'log'      => new LogAuditStore(app(LogManager::class), new NdjsonFormatter, 'null'),
        ]));

        $reads    = new \ArrayObject;
        $subjects = (static function () use ($reads): \Generator {
            $reads->append(true);

            yield Reference::of('tag', '1');
        })();

        try {
            AuditLog::bulk(self::CODE, $subjects)->record();

            self::fail('Expected the bulk operation to be refused.');
        } catch (\LogicException $exception) {
            $message = 'The store %s does not keep attachments, so a bulk operation cannot be stored there. Bind one that does, such as the database store.';

            self::assertSame(sprintf($message, StackAuditStore::class), $exception->getMessage());
        }

        self::assertCount(0, $reads);
        $this->assertNothingWritten();
    }

    /**
     * A manifest over its count or its byte bound is refused, never truncated,
     * and nothing is written; the same subjects within the bounds are recorded
     * whole.
     *
     * @return void
     */
    public function testAnOversizeManifestIsRefusedAndNothingIsWritten(): void
    {
        $config = app(ConfigRepository::class);
        $long   = array_map(static fn (int $index): Reference => Reference::of('tag', str_pad((string) $index, 100, 'x')), range(1, self::SUBJECTS));

        $config->set('audit-log.capture.bulk.max_members', self::SUBJECTS - 1);

        $this->assertRefused(Tag::query()->get(), 'A bulk operation names at most 999 subjects, the `audit-log.capture.bulk.max_members` setting.');

        $config->set('audit-log.capture.bulk.max_members', self::SUBJECTS);
        $config->set('audit-log.capture.bulk.max_bytes', 65536);

        $this->assertRefused($long, 'A bulk operation\'s manifest must encode to at most 65536 bytes, the `audit-log.capture.bulk.max_bytes` setting.');
        $this->assertNothingWritten();

        AuditLog::bulk(self::CODE, Tag::query()->get())->record();

        self::assertSame(1, self::artifacts()->where('member_count', self::SUBJECTS)->count());
    }

    /**
     * A sealed bulk entry verifies beside a plain one, its artifact checked
     * with its seal.
     *
     * @return void
     */
    public function testASealedBulkEntryVerifies(): void
    {
        $this->registerIntegrityCommands();

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
        app()->instance(Clock::class, FrozenClock::at(self::RECORDED_AT));

        AuditLog::record('tag.renamed');
        AuditLog::bulk(self::CODE, Tag::query()->get())->record();

        $this->sealAt(self::SEALED_AT);
        $this->sealAll();

        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        [$exit, $output] = $this->verify();

        self::assertSame(0, $exit, $output);
        self::assertStringContainsString(sprintf("seal 1 %s integrity=valid anchoring=unanchored members=2\n", $this->sealIdAt(1)), $output);
    }

    /**
     * Assert the bulk operation of the subjects is refused with the message,
     * before anything is written.
     *
     * @param  iterable<array-key, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @param  string  $message
     * @return void
     */
    private function assertRefused(iterable $subjects, string $message): void
    {
        try {
            AuditLog::bulk(self::CODE, $subjects)->record();

            self::fail('Expected the manifest to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        $this->assertNothingWritten();
    }

    /**
     * Assert no entry and no artifact is stored.
     *
     * @return void
     */
    private function assertNothingWritten(): void
    {
        self::assertSame(0, self::entries()->count());
        self::assertSame(0, self::artifacts()->count());
    }

    /**
     * The stored entry's properties, decoded.
     *
     * @return array<string, array<string, array<string, int|string>>>
     */
    private static function storedProperties(): array
    {
        $json = self::entries()->value('properties');

        self::assertIsString($json);

        $properties = json_decode($json, true, 16, JSON_THROW_ON_ERROR);

        self::assertIsArray($properties);

        /** @var array<string, array<string, array<string, int|string>>> $properties */
        return $properties;
    }

    /**
     * A query of the entries table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function entries(): Builder
    {
        return DB::connection(self::CONNECTION)->table(EntrySettings::table());
    }

    /**
     * A query of the artifacts table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function artifacts(): Builder
    {
        return DB::connection(self::CONNECTION)->table(EntrySettings::artifactsTable());
    }

    /**
     * Create the tags' table on the test's connection, and drop it before the
     * application is destroyed.
     *
     * @return void
     */
    private function createTagsTable(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(Tag::TABLE);
        $schema->create(Tag::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 64)->nullable();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(self::CONNECTION)->dropIfExists(Tag::TABLE);
        });
    }
}
