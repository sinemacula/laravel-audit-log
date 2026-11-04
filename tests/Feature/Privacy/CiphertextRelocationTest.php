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
 * Feature tests for what an envelope is bound to, read through the trail under
 * a scope that reveals the encrypted fields: an envelope reveals its value only
 * at the entry, the path, the list position and the column it was sealed for,
 * so one copied to another entry, moved to another path or column, swapped with
 * its neighbour in a list, or moved into or out of the IP address reads
 * `unreadable`; and a stored row edited to hold a copied envelope fails its
 * HMAC, so none of its fields reaches the reader.
 *
 * The keys are made through the key creator and the envelopes sealed with the
 * field cipher, as the package's encrypter seals them; the entries are stored
 * through the database store, each signed as captured, so only the envelope's
 * own binding decides, but where the test edits the stored row.
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
     * Bind the read path with the package's reader, reveal every encrypted
     * field, and make the owner's key.
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
     * An envelope copied, as it is, to the same path of another entry reads
     * `unreadable` there, while the entry it was sealed for still reveals it.
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
     * An envelope moved within its own entry, to another key, to a shallower
     * path or into the context, reads `unreadable` there, while one left at its
     * path reveals its value.
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
     * Envelopes are bound to the index their element is stored at: in the order
     * they were sealed for each reveals its value, and swapped each reads
     * `unreadable`.
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
     * An address sealed for the IP address reveals it there; a property's
     * envelope moved into the IP address, and the address's envelope moved into
     * a property, each read `unreadable`.
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
     * A stored row edited to hold an envelope copied from another entry fails
     * its HMAC: every envelope it holds, its own untouched one included, reads
     * `unreadable` and never reaches the reader, while the entry the envelope
     * was copied from still reveals it.
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
     * The value sealed under the owner's key as an envelope at the entry and
     * the path.
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
