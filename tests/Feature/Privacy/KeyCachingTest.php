<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\TestCase;

/**
 * Feature tests that no key outlives one operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyEncrypter::class)]
#[CoversClass(SubjectKeyFieldReader::class)]
#[CoversClass(Eraser::class)]
final class KeyCachingTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, ServesRequestsThroughOctane;

    /** @var string When every capture and erasure runs. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var string The code a card charge is captured under. */
    private const string CARD = 'billing.card_charged';

    /** @var string The category of the code. */
    private const string CATEGORY = 'billing';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, bind the key services afresh, and define the code.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $this->bindReading();

        self::define(EventDefinition::for(self::CARD)->category(self::CATEGORY)->retain('amount')->encrypt('card', KeyOwner::ACTOR));
    }

    /**
     * Remove the files this test wrote and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A worker writing after an erasure never encrypts under the erased key.
     *
     * @return void
     */
    public function testAWorkerWritingAfterAnErasureNeverEncryptsUnderTheErasedKey(): void
    {
        $kept   = app(SubjectKeyEncrypter::class);
        $before = $kept->encrypt(self::owner(), '"4242"', $this->context(Str::uuid7()->toString()));
        $first  = $this->chargeCard(self::owner());

        self::assertNotNull($before);
        self::assertSame($this->liveKeyOf(self::owner())->id, $before['k']);
        self::assertSame($before['k'], self::envelopeOf($first)['k']);

        $this->erase(self::owner());

        $after = $this->chargeCard(self::owner());

        self::assertNull($kept->encrypt(self::owner(), '"4242"', $this->context(Str::uuid7()->toString())));
        self::assertArrayNotHasKey('card', $after->properties ?? []);
        self::assertSame([KeyState::ERASED], array_values(array_map(static fn (SubjectKeyRow $key): KeyState => $key->state, $this->storedSubjectKeys())));
    }

    /**
     * A page read after an erasure shows the owner's fragments erased.
     *
     * @return void
     */
    public function testAPageReadAfterAnErasureShowsErased(): void
    {
        $record = $this->chargeCard(self::owner());
        $field  = EncryptedField::fromEnvelope($record->id, ['properties', 'card'], self::envelopeOf($record));
        $reader = app(SubjectKeyFieldReader::class);

        self::assertNotNull($field);

        $this->revealEverything();

        self::assertSame('4242', $this->cardOf($record->id));
        self::assertSame([null, '4242'], [$reader->readAll([$field])[0]->state, $reader->readAll([$field])[0]->value]);

        $this->erase(self::owner());

        self::assertSame(self::ERASED, $this->cardOf($record->id));
        self::assertSame(FieldState::ERASED, $reader->readAll([$field])[0]->state);
    }

    /**
     * An import after an erasure drops the owner's fields and makes no key.
     *
     * @return void
     */
    public function testAnImportChunkAfterAnErasureDropsTheErasedOwnersFields(): void
    {
        $other = Reference::of('App\Models\User', '43');

        // The source names the log journal rows are signed into
        app(ConfigRepository::class)->set('audit-log.source.id', 'app-eu-1');

        $this->chargeCard(self::owner());
        $this->erase(self::owner());

        $keys   = count($this->storedSubjectKeys());
        $result = $this->import([self::owner(), $other]);

        self::assertSame(2, $result->imported);

        $imported = $this->keyConnection()->table(EntrySettings::table())->whereNotNull('source_record_id')->orderBy('source_record_id')->pluck('properties')->all();

        self::assertCount(2, $imported);
        self::assertIsString($imported[0]);
        self::assertIsString($imported[1]);

        $erased = json_decode($imported[0], true, 64, JSON_THROW_ON_ERROR);
        $kept   = json_decode($imported[1], true, 64, JSON_THROW_ON_ERROR);

        self::assertIsArray($erased);
        self::assertIsArray($kept);
        self::assertArrayNotHasKey('card', $erased);
        self::assertSame(['count' => 1, 'paths' => ['card']], $erased['_audit']['omitted'] ?? null);
        self::assertSame($this->liveKeyOf($other)->id, $kept['card']['k'] ?? null);
        self::assertCount($keys + 1, $this->storedSubjectKeys());
    }

    /**
     * The encrypter is resolved per record and the reader per page.
     *
     * @return void
     */
    public function testTheEncrypterAndReaderAreResolvedAfresh(): void
    {
        $encrypters = new \ArrayObject;
        $readers    = new \ArrayObject;

        app()->bind(FieldEncrypter::class, static function () use ($encrypters): FieldEncrypter {
            $encrypter = app(SubjectKeyEncrypter::class);

            $encrypters->append(spl_object_id($encrypter));

            return $encrypter;
        });

        app()->bind(FieldReader::class, static function () use ($readers): FieldReader {
            $reader = app(SubjectKeyFieldReader::class);

            $readers->append(spl_object_id($reader));

            return $reader;
        });

        $first  = $this->chargeCard(self::owner());
        $second = $this->chargeCard(self::owner());

        $this->revealEverything();

        $this->cardOf($first->id);
        $this->cardOf($second->id);

        self::assertGreaterThanOrEqual(2, count($encrypters));
        self::assertCount(count($encrypters), array_unique($encrypters->getArrayCopy()));
        self::assertGreaterThanOrEqual(2, count($readers));
        self::assertNotSame(app(SubjectKeyEncrypter::class), app(SubjectKeyEncrypter::class));
        self::assertNotSame(app(SubjectKeyFieldReader::class), app(SubjectKeyFieldReader::class));
    }

    /**
     * Requests on one Octane worker share no key.
     *
     * @return void
     */
    public function testOctaneRequestsShareNoKey(): void
    {
        $encrypters = new \ArrayObject;

        app()->bind(FieldEncrypter::class, static function () use ($encrypters): FieldEncrypter {
            $encrypter = app(SubjectKeyEncrypter::class);

            $encrypters->append(spl_object_id($encrypter));

            return $encrypter;
        });

        Route::get('/charge', static function (Request $request): array {
            $owner = Reference::of('App\Models\User', (string) $request->query('owner'));

            return AuditLog::event(self::CARD)->by($owner)->withProperties(['amount' => '12.00', 'card' => '4242'])->record()->toArray();
        });

        $this->bootOctaneWorker();

        $first = $this->serve(self::octaneRequest('GET', '/charge', ['owner' => '42']))->json('properties');

        $this->erase(self::owner());

        $second = $this->serve(self::octaneRequest('GET', '/charge', ['owner' => '42']))->json('properties');
        $third  = $this->serve(self::octaneRequest('GET', '/charge', ['owner' => '43']))->json('properties');

        self::assertIsArray($first);
        self::assertIsArray($second);
        self::assertIsArray($third);
        self::assertArrayNotHasKey('card', $second);
        self::assertIsArray($first['card'] ?? null);
        self::assertIsArray($third['card'] ?? null);
        self::assertNotSame($first['card']['k'] ?? null, $third['card']['k'] ?? null);
        self::assertSame($this->liveKeyOf(Reference::of('App\Models\User', '43'))->id, $third['card']['k'] ?? null);
        // One per record, and one the erasure resolves to know the binding
        self::assertCount(4, $encrypters);
        self::assertCount(4, array_unique($encrypters->getArrayCopy()));
    }

    /**
     * Capture a card charge encrypted under the actor's key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function chargeCard(Reference $actor): AuditRecord
    {
        return AuditLog::event(self::CARD)->by($actor)->withProperties(['amount' => '12.00', 'card' => '4242'])->record();
    }

    /**
     * Erase the owner, all or nothing, with the eraser the container builds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return void
     */
    private function erase(Reference $owner): void
    {
        app(Eraser::class)->erase('01932b4e-9000-7000-8000-0000000000a1', $owner, self::authority(), false, false);
    }

    /**
     * The card of the entry, as a page shows it to the viewer.
     *
     * @param  string  $id
     * @return string
     */
    private function cardOf(string $id): string
    {
        foreach (app(AuditTrail::class)->visibleTo($this->viewer())->inCategory(self::CATEGORY)->cursorPaginate(50)->entries as $entry) {
            if ($entry->id === $id) {
                $card = $entry->properties['card'] ?? null;

                self::assertIsString($card);

                return $card;
            }
        }

        self::fail("The page does not show {$id}.");
    }

    /**
     * The card envelope the record holds; the test fails without one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return array{v: int, k: string, c: string}
     */
    private static function envelopeOf(AuditRecord $record): array
    {
        $envelope = $record->properties['card'] ?? null;

        self::assertIsArray($envelope);
        self::assertIsInt($envelope['v'] ?? null);
        self::assertIsString($envelope['k'] ?? null);
        self::assertIsString($envelope['c'] ?? null);

        return ['v' => $envelope['v'], 'k' => $envelope['k'], 'c' => $envelope['c']];
    }

    /**
     * The owner's live key in the code's category; the test fails without one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private function liveKeyOf(Reference $owner): SubjectKeyRow
    {
        $unit = (new KeyUnit($owner, null, self::CATEGORY))->digest();
        $keys = array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->unit === $unit && $key->state === KeyState::LIVE));

        self::assertCount(1, $keys, 'The owner has no live key, or more than one.');

        return $keys[0];
    }

    /**
     * The context the owner's card is encrypted in at the entry.
     *
     * @param  string  $entryId
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldContext
     */
    private function context(string $entryId): FieldContext
    {
        return new FieldContext($entryId, ['properties', 'card'], app(SealSettings::class)->logId(), null, self::CATEGORY, [self::owner()]);
    }

    /**
     * Import a file of a card charge by each actor, in order.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $actors
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     */
    private function import(array $actors): ImportResult
    {
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);

        $lines = '';

        foreach ($actors as $index => $actor) {
            $lines .= json_encode([
                'format'           => 'audit-log-import/v1',
                'source_record_id' => sprintf('rec-%d', $index + 1),
                'occurred_at'      => '2026-10-01T09:00:00.000001Z',
                'event'            => self::CARD,
                'outcome'          => 'success',
                'actor'            => ['type' => $actor->type, 'id' => $actor->id],
                'properties'       => ['amount' => '12.00', 'card' => '4242'],
            ], JSON_THROW_ON_ERROR) . "\n";
        }

        $path = tempnam(sys_get_temp_dir(), 'audit-log-key-caching');

        self::assertIsString($path);

        $this->files[] = $path;

        file_put_contents($path, $lines);

        return app(AuditImporter::class)->import(ImportSource::fromFile($path, 'crm-eu'), self::authority(), false);
    }

    /**
     * The owner every test erases.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\User', '42');
    }

    /**
     * The authority every erasure and import is made with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }

    /**
     * Register the definition as the only one, as an application does at boot.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     */
    private static function define(EventDefinition $definition): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define($definition);

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }
}
