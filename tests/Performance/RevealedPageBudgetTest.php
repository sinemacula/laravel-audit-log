<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\KeyUses;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;

/**
 * Statement budget for revealing a page of the trail, measured against a page
 * read in the same process: revealing adds one key select, and erased keys one
 * journal select, however many entries it holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyFieldReader::class)]
final class RevealedPageBudgetTest extends PerformanceContractTestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var list<string> The properties each encrypted entry seals, one per owner, in order. */
    private const array FIELDS = ['card', 'pin', 'note'];

    /** @var int How many encrypted entries a page holds. */
    private const int ENTRIES = 20;

    /** @var int How many entries the largest page holds: the greatest `read.max_per_page`. */
    private const int LARGEST_PAGE = 500;

    /** @var string The data key of every key the largest page's entries are sealed under. */
    private const string DATA_KEY = 'a data key of thirty-two bytes!!';

    /**
     * Bind the read path with the package's reader.
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
    }

    /**
     * A revealed page asks for its keys once a page, never per field, entry or
     * owner.
     *
     * @return void
     */
    public function testARevealingPageAsksForItsKeysOnce(): void
    {
        $this->seedEncrypted($this->owners());

        foreach ([1, self::ENTRIES] as $perPage) {
            $this->allowEverything();

            $sealed = $this->statementsOf($perPage);

            $this->revealEverything();

            $revealed = $this->statementsOf($perPage);
            $keyReads = self::touching($revealed, KeyTables::subjectKeysTable());

            self::assertCount(count($sealed) + 1, $revealed, "A revealed page of {$perPage} costs one statement more than the same page sealed.");
            self::assertCount(1, $keyReads, "A revealed page of {$perPage} reads its keys once.");
            self::assertStringStartsWith('select', strtolower($keyReads[0]));
            self::assertSame($sealed, array_values(array_diff($revealed, $keyReads)));
            self::assertSame([], self::touching($revealed, LifecycleTables::journalTable()));
        }
    }

    /**
     * The largest page names 1,500 keys, more than SQLite's oldest builds bind
     * at once: SQLite reads them 400 to a statement, other engines in one.
     *
     * @return void
     */
    public function testTheLargestPageRevealsMoreKeysThanSqliteBindsAtOnce(): void
    {
        app(ConfigRepository::class)->set('audit-log.read.max_per_page', self::LARGEST_PAGE);

        $first = new CarbonImmutable('2026-11-02T12:00:00.000000Z', 'UTC');

        for ($index = 0; $index < self::LARGEST_PAGE; $index++) {
            $id         = Str::uuid7()->toString();
            $properties = [];

            foreach (self::FIELDS as $name) {
                $key = $this->signedSubjectKey(new KeyUnit(Reference::of('App\Models\User', "{$name}-{$index}"), null, self::KEY_CATEGORY), 1, self::DATA_KEY);

                $this->insertSubjectKey($key);

                $properties[$name] = $this->sealEnvelope(self::DATA_KEY, $key->id, "{$name} {$index}", $id, ['properties', $name]);
            }

            $this->seedEntry(['properties' => $properties], StoredTime::format($first->addMicroseconds($index)), $id);
        }

        $this->revealEverything();

        $page     = $this->capture(fn (): TrailPage => app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->cursorPaginate(self::LARGEST_PAGE));
        $keyReads = self::touching($this->capturedStatements(), KeyTables::subjectKeysTable());
        $keys     = count(self::FIELDS) * self::LARGEST_PAGE;
        $expected = $this->keyConnection()->getDriverName() === 'sqlite' ? (int) ceil($keys / KeyUses::SQLITE_ROWS_PER_STATEMENT) : 1;

        $shown = [];

        foreach ($page->entries as $entry) {
            foreach (self::FIELDS as $name) {
                $shown[] = $entry->properties[$name] ?? null;
            }
        }

        self::assertCount(self::LARGEST_PAGE, $page->entries);
        self::assertCount($expected, $keyReads);
        self::assertSame([], array_values(array_filter($shown, static fn (mixed $value): bool => !is_string($value) || str_starts_with($value, '['))));
        self::assertCount($keys, $shown);
    }

    /**
     * A page that is not revealed costs what it did with no encrypted field,
     * reading no key or journal.
     *
     * @return void
     */
    public function testANonRevealingPageAsksForNoKey(): void
    {
        $this->allowEverything();
        $this->seedEntries(self::ENTRIES);

        $plain = $this->statementsOf(self::ENTRIES);

        $this->seedEncrypted($this->owners());

        $sealed = $this->statementsOf(self::ENTRIES);

        self::assertSame($plain, $sealed);
        self::assertSame([], self::touching($sealed, KeyTables::subjectKeysTable()));
        self::assertSame([], self::touching($sealed, LifecycleTables::journalTable()));
    }

    /**
     * An erased key adds one journal select, and two owners' erased keys under
     * two erasures still only one.
     *
     * @return void
     */
    public function testAPageWithAnErasedKeyAddsOneJournalRead(): void
    {
        $owners = $this->owners();

        $this->seedEncrypted($owners);
        $this->revealEverything();

        $live = $this->statementsOf(self::ENTRIES);

        $this->eraseByHand($owners[0]);

        $one = $this->statementsOf(self::ENTRIES);

        $this->eraseByHand($owners[1]);

        $two = $this->statementsOf(self::ENTRIES);

        foreach (['one erasure' => $one, 'two erasures' => $two] as $label => $erased) {
            $journalReads = self::touching($erased, LifecycleTables::journalTable());

            self::assertCount(count($live) + 1, $erased, "A page under {$label} costs one statement more.");
            self::assertCount(1, $journalReads, "A page under {$label} reads the journal once.");
            self::assertStringStartsWith('select', strtolower($journalReads[0]));
            self::assertSame($live, array_values(array_diff($erased, $journalReads)));
        }
    }

    /**
     * The three owners the encrypted entries seal a field for.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     */
    private function owners(): array
    {
        return array_map(static fn (string $id): Reference => Reference::of('App\Models\User', $id), ['41', '42', '43']);
    }

    /**
     * Seed the encrypted entries, each field sealed under its owner's key, each
     * a microsecond after every entry already seeded.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     * @return void
     */
    private function seedEncrypted(array $owners): void
    {
        $keys  = array_map(fn (Reference $owner): array => $this->makeSubjectKey($owner), $owners);
        $first = new CarbonImmutable('2026-11-02T12:00:00.000000Z', 'UTC');

        for ($index = 0; $index < self::ENTRIES; $index++) {
            $id         = Str::uuid7()->toString();
            $properties = [];

            foreach (self::FIELDS as $position => $name) {
                [$key, $dataKey] = $keys[$position];

                $properties[$name] = $this->sealEnvelope($dataKey, $key->id, "{$name} {$index}", $id, ['properties', $name]);
            }

            $this->seedEntry(['properties' => $properties], StoredTime::format($first->addMicroseconds($index)), $id);
        }
    }

    /**
     * The statements a page of the trail asks for, read for the viewer under
     * the bound policy.
     *
     * @param  int  $perPage
     * @return list<string>
     */
    private function statementsOf(int $perPage): array
    {
        $page = $this->capture(fn (): TrailPage => app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->cursorPaginate($perPage));

        self::assertCount($perPage, $page->entries);

        return $this->capturedStatements();
    }

    /**
     * The statements naming the table as its engine quotes it, so a table whose
     * name starts with it is not counted.
     *
     * @param  list<string>  $statements
     * @param  string  $table
     * @return list<string>
     */
    private static function touching(array $statements, string $table): array
    {
        $pattern = '/[`"]' . preg_quote($table, '/') . '[`"]/';

        return array_values(array_filter($statements, static fn (string $statement): bool => preg_match($pattern, $statement) === 1));
    }
}
