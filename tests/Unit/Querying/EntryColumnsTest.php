<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\EntryColumns;
use SineMacula\Laravel\AuditLog\Querying\StoredEntry;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the columns of a stored entry as a shown entry holds them: the
 * entry built of them with what was projected, a concealed reason, references
 * of both their columns or none, the origin, the manifest descriptor the
 * artifact inspector accepts, and the refusal naming a column the entry cannot
 * hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EntryColumns::class)]
final class EntryColumnsTest extends TestCase
{
    /** @var string The entry's id. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string An HMAC-SHA256 in lower-case hex. */
    private const string HMAC = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /**
     * The entry holds the stored columns, typed, and exactly the properties,
     * context and address it is given, never the stored ones.
     *
     * @return void
     */
    public function testTheEntryHoldsTheColumnsAndWhatWasProjected(): void
    {
        $stored = self::stored(['outcome' => 'denied', 'reason' => 'over_limit']);
        $entry  = EntryColumns::entry($stored, false, ['card' => '[ENCRYPTED]'], ['route' => 'x'], '[ERASED]');

        self::assertSame(self::ID, $entry->id);
        self::assertSame('invoice.approved', $entry->event);
        self::assertSame([1, 1, 1], [$entry->eventVersion, $entry->recordVersion, $entry->integrityVersion]);
        self::assertSame('finance', $entry->category);
        self::assertSame(Outcome::DENIED, $entry->outcome);
        self::assertSame('over_limit', $entry->reason);
        self::assertEquals(Reference::of('user', '42'), $entry->actor);
        self::assertSame(Origin::HTTP, $entry->origin);
        self::assertSame(Provenance::CAPTURED, $entry->provenance);
        self::assertSame(['card' => '[ENCRYPTED]'], $entry->properties);
        self::assertSame(['route' => 'x'], $entry->context);
        self::assertSame('[ERASED]', $entry->ip);
        self::assertSame(['k1', self::HMAC], [$entry->keyId, $entry->hmac]);
        self::assertSame(RecordFactory::OCCURRED_AT, $entry->toArray()['occurred_at']);
        self::assertSame(RecordFactory::RECORDED_AT, $entry->toArray()['recorded_at']);
        self::assertNull($entry->manifest);
    }

    /**
     * A concealed entry shows no reason, whatever is stored.
     *
     * @return void
     */
    public function testAConcealedReasonIsNone(): void
    {
        $stored = self::stored(['outcome' => 'failure', 'reason' => 'account_rate_limited']);

        self::assertNull(EntryColumns::entry($stored, true, [], [], null)->reason);
        self::assertSame('account_rate_limited', EntryColumns::entry($stored, false, [], [], null)->reason);
    }

    /**
     * A reference is made only when both of its columns are stored.
     *
     * @return void
     */
    public function testAReferenceNeedsBothColumns(): void
    {
        $envelope = ['actor_type' => 'user', 'actor_id' => '42', 'subject_type' => 'invoice', 'subject_id' => null, 'tenant_type' => null, 'tenant_id' => '7'];

        self::assertEquals(Reference::of('user', '42'), EntryColumns::reference($envelope, 'actor'));
        self::assertNull(EntryColumns::reference($envelope, 'subject'));
        self::assertNull(EntryColumns::reference($envelope, 'tenant'));
    }

    /**
     * The origin is its enum, none when none is stored, and a value no origin
     * holds is refused naming the column.
     *
     * @return void
     */
    public function testTheOriginIsItsEnumOrNone(): void
    {
        self::assertSame(Origin::QUEUE, EntryColumns::origin(['origin' => 'queue']));
        self::assertNull(EntryColumns::origin(['origin' => null]));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored entry\'s `origin` cannot be shown.');

        EntryColumns::origin(['origin' => 'carrier_pigeon']);
    }

    /**
     * Rows of `[column, stored value]`: enum columns whose stored value the
     * shown entry cannot hold.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnknownEnums(): iterable
    {
        yield from [
            'an unknown outcome'    => ['outcome', 'maybe'],
            'an unknown provenance' => ['provenance', 'rumoured'],
        ];
    }

    /**
     * An entry whose outcome or provenance no enum holds is refused, naming the
     * column and never its value.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideUnknownEnums')]
    public function testAnUnknownEnumIsRefusedNamingTheColumn(string $column, string $value): void
    {
        $stored = StoredEntry::fromRow([$column => $value] + self::row(), new RowCodec);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('A stored entry\'s `%s` cannot be shown.', $column));

        EntryColumns::entry($stored, false, [], [], null);
    }

    /**
     * The manifest is the kind, count and digest of a descriptor the artifact
     * inspector accepts, never its artifact id, and none without one.
     *
     * @return void
     */
    public function testTheManifestIsTheAcceptedDescriptorsKindCountAndDigest(): void
    {
        $finalised = RecordFactory::finalisedWithArtifact(ArtifactKind::DISCLOSURE, RecordFactory::canonical(ArtifactKind::DISCLOSURE, 2), 2);
        $stored    = StoredEntry::fromRow((new RowCodec)->encode($finalised), new RowCodec);

        self::assertNotNull($finalised->record->attachment);
        self::assertSame(['kind' => 'disclosure', 'count' => 2, 'digest' => $finalised->record->attachment->digest], EntryColumns::manifest($stored));
        self::assertNull(EntryColumns::manifest(self::stored()));
    }

    /**
     * Each column reader reads the column as the codec decoded it.
     *
     * @return void
     */
    public function testTheColumnReadersReadTheColumn(): void
    {
        $envelope = ['event' => 'invoice.approved', 'reason' => null, 'guard' => 'web', 'event_version' => 3];

        self::assertSame('invoice.approved', EntryColumns::text($envelope, 'event'));
        self::assertNull(EntryColumns::nullable($envelope, 'reason'));
        self::assertSame('web', EntryColumns::nullable($envelope, 'guard'));
        self::assertSame(3, EntryColumns::integer($envelope, 'event_version'));
        self::assertSame('A stored entry\'s `properties` cannot be shown.', EntryColumns::malformed('properties')->getMessage());
    }

    /**
     * `EntryColumns` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(EntryColumns::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(EntryColumns::class, $instance);
    }

    /**
     * A stored entry of a captured record of an approved invoice, with the
     * fields given in place of its own.
     *
     * @param  array<string, ?string>  $fields
     * @return \SineMacula\Laravel\AuditLog\Querying\StoredEntry
     */
    private static function stored(array $fields = []): StoredEntry
    {
        return StoredEntry::fromRow(self::row($fields), new RowCodec);
    }

    /**
     * The stored row of a captured record of an approved invoice, with the
     * fields given in place of its own, finalised at `RECORDED_AT`.
     *
     * @param  array<string, ?string>  $fields
     * @return array<string, int|string|null>
     */
    private static function row(array $fields = []): array
    {
        $record = RecordFactory::withFields(['id' => self::ID, ...$fields], RecordFactory::captured(id: self::ID));

        return (new RowCodec)->encode(new FinalisedRecord($record, RecordFactory::RECORDED_AT, 1, 'k1', self::HMAC));
    }
}
