<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Lifecycle\KeyUseRebuildResult;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Rebuilds the key uses from the entries they describe, adding the rows that
 * are missing and never removing one.
 *
 * The entries are read on the storage connection's writer in pages of 1,000, by
 * id, each page after the last id of the one before, so a page seeks the
 * primary key and the rebuild holds one page at a time. Each entry's signature
 * is verified first, and only a verified entry is trusted: one whose signature
 * does not match, whose signing key the ring does not hold, or that cannot be
 * read is skipped and adds nothing. The keys a verified entry's envelopes name
 * are found exactly as the store finds them when it writes the entry, and the
 * key uses of the page already stored are read through the entry index, so a
 * row is added only when it is missing; the missing rows are inserted many to a
 * statement, and a dry run counts them and writes nothing.
 *
 * Key uses are an append-only index, and the rebuild keeps them so: a key use
 * no verified entry names, of an entry pruned or tampered with, is left where
 * it is, since removing evidence is never a repair. Its rows are written by the
 * storage connection's own role, which inserts key uses as every write does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyUseRebuilder
{
    /** @var int Entries read by one statement. */
    public const int PAGE = 1000;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     */
    public function __construct(

        /** The manager the storage connection is resolved from on every rebuild. */
        private DatabaseManager $database,

        /** Verifies each entry before what it names is trusted. */
        private RecordSigner $signer,

        /** Decodes each stored entry. */
        private RowCodec $codec,
    ) {}

    /**
     * Add every key use a verified entry names and the table lacks, or with
     * `$dryRun` count them, and return what the rebuild read and added.
     *
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\KeyUseRebuildResult
     *
     * @throws \InvalidArgumentException
     */
    public function rebuild(bool $dryRun = false): KeyUseRebuildResult
    {
        $connection = $this->database->connection(StorageConnection::name());
        $entries    = 0;
        $verified   = 0;
        $added      = 0;
        $after      = null;

        do {
            $page = self::entriesAfter($connection, $after);

            [$trusted, $uses] = $this->usesOf($page);

            $missing = self::missingOf($connection, $uses);

            if (!$dryRun) {
                KeyUses::insert($connection, $missing);
            }

            $entries  += count($page);
            $verified += $trusted;
            $added    += count($missing);
            $after = self::lastIdOf($page) ?? $after;
        } while (count($page) === self::PAGE);

        return new KeyUseRebuildResult($entries, $verified, $entries - $verified, $added, $dryRun);
    }

    /**
     * How many of the page's entries verified, and the key uses they name, each
     * entry's sorted by key.
     *
     * @param  list<array<string, scalar|null>>  $page
     * @return array{0: int, 1: list<array{key_id: string, entry_id: string}>}
     *
     * @throws \InvalidArgumentException
     */
    private function usesOf(#[\SensitiveParameter] array $page): array
    {
        $verified = 0;
        $uses     = [];

        foreach ($page as $row) {
            $envelope = $this->verified($row);

            $id = $envelope['id'] ?? null;
            $ip = $envelope['ip'] ?? null;

            if (!is_string($id)) {
                continue;
            }

            $verified++;

            array_push($uses, ...KeyUses::rowsFor($id, EnvelopeKeys::of($envelope['properties'] ?? null, $envelope['context'] ?? null, is_string($ip) ? $ip : null)));
        }

        return [$verified, $uses];
    }

    /**
     * The decoded entry when its signature verifies under the key it names, and
     * `null` when it does not, when the ring does not hold that key, or when
     * the row cannot be read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, scalar|null>  $row
     * @return ?array<string, mixed>
     */
    private function verified(#[\SensitiveParameter] array $row): ?array
    {
        try {
            $envelope = $this->codec->decode($row);

            return $this->signer->verifies($envelope) ? $envelope : null;
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // An entry that cannot be judged says nothing that can be trusted,
            // so it adds no key use
            return null;
        }
    }

    /**
     * Up to a page of entries after the id, or from the first, in id order, on
     * the connection's writer, each as its stored row.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  ?string  $after
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    private static function entriesAfter(Connection $connection, ?string $after): array
    {
        $query = $connection->table(EntrySettings::table())->useWritePdo()->orderBy('id')->limit(self::PAGE);

        if ($after !== null) {
            $query->where('id', '>', $after);
        }

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (object $stored): array => (array) $stored, $query->get()->all()));
    }

    /**
     * The key uses that are not stored yet, read through the entry index a
     * statement's worth of entries at a time.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<array{key_id: string, entry_id: string}>  $uses
     * @return list<array{key_id: string, entry_id: string}>
     *
     * @throws \InvalidArgumentException
     */
    private static function missingOf(Connection $connection, array $uses): array
    {
        $entryIds = array_values(array_unique(array_column($uses, 'entry_id')));
        $stored   = [];

        foreach (array_chunk($entryIds, KeyUses::rowsPerStatement($connection)) as $chunk) {
            foreach ($connection->table(KeyTables::keyUsesTable())->useWritePdo()->whereIn('entry_id', $chunk)->get(['key_id', 'entry_id']) as $use) {
                $stored[self::pairOf((string) $use->key_id, (string) $use->entry_id)] = true;
            }
        }

        return array_values(array_filter($uses, static fn (array $use): bool => !array_key_exists(self::pairOf($use['key_id'], $use['entry_id']), $stored)));
    }

    /**
     * The id of the page's last entry, or `null` for an empty page.
     *
     * @param  list<array<string, scalar|null>>  $page
     * @return ?string
     */
    private static function lastIdOf(#[\SensitiveParameter] array $page): ?string
    {
        $last = $page === [] ? null : $page[array_key_last($page)]['id'] ?? null;

        return is_string($last) ? $last : null;
    }

    /**
     * One key use's key and entry, as one text.
     *
     * @param  string  $keyId
     * @param  string  $entryId
     * @return string
     */
    private static function pairOf(string $keyId, string $entryId): string
    {
        return $keyId . ' ' . $entryId;
    }
}
