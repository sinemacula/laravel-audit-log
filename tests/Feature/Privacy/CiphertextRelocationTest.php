<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\TestCase;

/**
 * Feature tests that an envelope reveals its value only where it was sealed.
 *
 * Entries are signed as captured, so only the envelope's binding decides,
 * except where a test edits the stored row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyFieldReader::class)]
#[CoversClass(EntryProjector::class)]
final class CiphertextRelocationTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var string What a field reads as when it cannot be read. */
    private const string UNREADABLE = '[UNREADABLE]';

    /** @var list<string> The path a card number is sealed at. */
    private const array CARD = ['properties', 'card'];

    /** @var list<string> The path of an encrypted IP address. */
    private const array IP = ['ip'];

    /** @var string The data key of the owner every envelope is sealed for. */
    private string $dataKey = '';

    /** @var string The id of the owner's key, which every envelope names. */
    private string $keyId = '';

    /**
     * Bind the reader, reveal every encrypted field, and make the owner's key.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $this->bindReading();
        $this->revealEverything();

        [$key, $this->dataKey] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        $this->keyId = $key->id;
    }

    /**
     * An envelope copied to another entry reads `unreadable` there.
     *
     * @return void
     */
    public function testAnEnvelopeCopiedToAnotherEntryIsUnreadable(): void
    {
        $first  = self::entryId();
        $second = self::entryId();
        $card   = $this->seal('4242', $first, self::CARD);

        $this->seedEntry(['properties' => ['card' => $card]], '2026-11-01T11:00:00.000000Z', $first);
        $this->seedEntry(['properties' => ['card' => $card]], '2026-11-01T11:00:01.000000Z', $second);

        $entries = $this->entries();

        self::assertSame('4242', $entries[$first]->properties['card']);
        self::assertSame(self::UNREADABLE, $entries[$second]->properties['card']);
    }

    /**
     * An envelope moved to another path or into the context reads `unreadable`.
     *
     * @return void
     */
    public function testAnEnvelopeMovedToAnotherPathIsUnreadable(): void
    {
        $id    = self::entryId();
        $card  = $this->seal('4242', $id, self::CARD);
        $last4 = $this->seal('4242', $id, ['properties', 'payment', 'last4']);

        $this->seedEntry([
            'properties' => ['card' => $card, 'pin' => $card, 'last4' => $last4, 'payment' => ['last4' => $last4]],
            'context'    => ['card' => $card],
        ], id: $id);

        $entry = $this->entries()[$id];

        self::assertSame('4242', $entry->properties['card']);
        self::assertSame(['last4' => '4242'], $entry->properties['payment']);
        self::assertSame(self::UNREADABLE, $entry->properties['pin']);
        self::assertSame(self::UNREADABLE, $entry->properties['last4']);
        self::assertSame(self::UNREADABLE, $entry->context['card']);
    }

    /**
     * Envelopes swapped between list positions read `unreadable`.
     *
     * @return void
     */
    public function testAnEnvelopeMovedBetweenListPositionsIsUnreadable(): void
    {
        $kept    = self::entryId();
        $swapped = self::entryId();

        $items = [
            $kept    => [$this->seal('first', $kept, ['properties', 'items', 0]), $this->seal('second', $kept, ['properties', 'items', 1])],
            $swapped => [$this->seal('second', $swapped, ['properties', 'items', 1]), $this->seal('first', $swapped, ['properties', 'items', 0])],
        ];

        $this->seedEntry(['properties' => ['items' => $items[$kept]]], '2026-11-01T11:00:00.000000Z', $kept);
        $this->seedEntry(['properties' => ['items' => $items[$swapped]]], '2026-11-01T11:00:01.000000Z', $swapped);

        $entries = $this->entries();

        self::assertSame(['first', 'second'], $entries[$kept]->properties['items']);
        self::assertSame([self::UNREADABLE, self::UNREADABLE], $entries[$swapped]->properties['items']);
    }

    /**
     * An envelope moved into or out of the IP address reads `unreadable`.
     *
     * @return void
     */
    public function testAnEnvelopeMovedToTheIpIsUnreadable(): void
    {
        $kept  = self::entryId();
        $moved = self::entryId();

        $this->seedEntry(['ip' => CanonicalEncoder::encode($this->seal('203.0.113.9', $kept, self::IP))], '2026-11-01T11:00:00.000000Z', $kept);
        $this->seedEntry([
            'ip'         => CanonicalEncoder::encode($this->seal('203.0.113.9', $moved, self::CARD)),
            'properties' => ['card' => $this->seal('203.0.113.9', $moved, self::IP)],
        ], '2026-11-01T11:00:01.000000Z', $moved);

        $entries = $this->entries();

        self::assertSame('203.0.113.9', $entries[$kept]->ip);
        self::assertSame(self::UNREADABLE, $entries[$moved]->ip);
        self::assertSame(self::UNREADABLE, $entries[$moved]->properties['card']);
    }

    /**
     * A row holding a copied envelope fails its HMAC, hiding every field.
     *
     * @return void
     */
    public function testARowEditedToHoldACopiedEnvelopeFailsItsHmac(): void
    {
        $source = self::entryId();
        $target = self::entryId();
        $card   = $this->seal('4242', $source, self::CARD);
        $pin    = $this->seal('1234', $target, ['properties', 'pin']);

        $this->seedEntry(['properties' => ['card' => $card]], '2026-11-01T11:00:00.000000Z', $source);
        $this->seedEntry(['properties' => ['pin' => $pin]], '2026-11-01T11:00:01.000000Z', $target);

        self::assertSame(['pin' => '1234'], $this->entries()[$target]->properties);

        DB::connection(StorageConnection::name())
            ->table(EntrySettings::table())
            ->where('id', $target)
            ->update(['properties' => json_encode(['card' => $card, 'pin' => $pin], JSON_THROW_ON_ERROR)]);

        $entries = $this->entries();
        $fields  = self::propertiesOf($this->readRecords('audit_log.trail_read')[1])['fields'];

        self::assertSame('4242', $entries[$source]->properties['card']);
        self::assertSame(self::UNREADABLE, $entries[$target]->properties['card']);
        self::assertSame(self::UNREADABLE, $entries[$target]->properties['pin']);
        self::assertSameProperties(['encrypted' => 0, 'erased' => 0, 'revealed' => 1, 'unreadable' => 2], $fields);
    }

    /**
     * The value sealed under the owner's key at the entry and path.
     *
     * @param  string  $value
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $path
     * @return array{v: int, k: string, c: string}
     */
    private function seal(string $value, string $entryId, array $path): array
    {
        return $this->sealEnvelope($this->dataKey, $this->keyId, $value, $entryId, $path);
    }

    /**
     * Every entry a page of the trail shows the viewer, by id.
     *
     * @return array<string, \SineMacula\Laravel\AuditLog\Querying\TrailEntry>
     */
    private function entries(): array
    {
        $entries = [];

        foreach (app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->cursorPaginate(50)->entries as $entry) {
            $entries[$entry->id] = $entry;
        }

        return $entries;
    }

    /**
     * A fresh entry id, as the pipeline mints one.
     *
     * @return string
     */
    private static function entryId(): string
    {
        return Str::uuid7()->toString();
    }
}
