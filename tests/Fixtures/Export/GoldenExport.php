<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Export;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * The generator of the golden version 1 export in `golden-v1`, kept to show how
 * its files were made; the suite never runs it and reads the files pinned by
 * their digests.
 *
 * It seeds two approvals and a bulk approval under the test `app.key`, exports
 * what an auditor may see as NDJSON at a fixed instant, and writes the export,
 * its bundle and the journal's rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GoldenExport
{
    /** @var string When the export is journalled. */
    public const string EXPORTED_AT = '2026-11-02T09:30:00.000000Z';

    /** @var list<string> When each approval occurred and was recorded. */
    public const array APPROVED_AT = ['2026-11-01T12:00:00.000001Z', '2026-11-01T12:00:00.000002Z'];

    /** @var string The type of the auditor the export is made for. */
    public const string VIEWER_TYPE = 'App\Models\Auditor';

    /** @var string The id of the auditor the export is made for. */
    public const string VIEWER_ID = 'auditor-1';

    /** @var string The name of the export's file in the directory. */
    public const string FILE = 'export.ndjson';

    /** @var string The name of the journal's rows in the directory. */
    public const string JOURNAL = 'journal.json';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Seed the entries, export them, and write the export, its bundle and the
     * journal's rows to the directory, which must not hold an export already.
     *
     * @param  string  $directory
     * @return void
     */
    public static function write(string $directory): void
    {
        app()->scopedIf(ReadGuard::class);
        app()->singletonIf(FieldReader::class, SealedFieldReader::class);
        app()->instance(AuditAccessPolicy::class, new ClosurePolicy(static fn (): AccessScope => AccessScope::all()));

        foreach (self::APPROVED_AT as $at) {
            $finaliser = new RecordFinaliser(FrozenClock::at($at), app(RecordSigner::class));

            app(DatabaseAuditStore::class)->store($finaliser->finalise(RecordFactory::captured(occurredAt: $at)));
        }

        app(DatabaseAuditStore::class)->store(RecordFactory::finalisedBundle(3));
        app()->instance(Clock::class, FrozenClock::at(self::EXPORTED_AT));

        $result = app(AuditTrail::class)->visibleTo(Reference::of(self::VIEWER_TYPE, self::VIEWER_ID))->export($directory . '/' . self::FILE);

        $connection = DB::connection(StorageConnection::name());
        $journal    = [
            'entry'    => (array) $connection->table(EntrySettings::table())->where('id', $result->entryId)->first(),
            'artifact' => (array) $connection->table(EntrySettings::artifactsTable())->where('entry_id', $result->entryId)->first(),
        ];

        $encoded = json_encode($journal, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        file_put_contents($directory . '/' . self::JOURNAL, $encoded . "\n");
    }
}
