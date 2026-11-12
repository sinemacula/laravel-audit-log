<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;

/**
 * Alters a sealed log through raw `DB::table()` calls below the package, as
 * someone who can write to its database could, then asks `audit-log:verify`
 * what it finds; only `forgeSeal()` signs, as a key holder could.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait TampersWithTheLog
{
    use SealsEntries;

    /** @var string The disk the disk anchor writes to, faked for each test. */
    protected const string ANCHOR_DISK = 'anchors';

    /** @var string The namespace on that disk the disk anchor writes under. */
    protected const string ANCHOR_PATH = 'audit-log-anchors';

    /**
     * Register the seal and verify commands with the console kernel, which
     * keeps the test independent of the provider.
     *
     * @return void
     */
    protected function registerIntegrityCommands(): void
    {
        $kernel = app(Kernel::class);

        $kernel->registerCommand(new SealCommand);
        $kernel->registerCommand(new VerifyCommand);
    }

    /**
     * Bind a disk anchor on a faked disk as the anchor every run anchors and
     * verifies with, and return it.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     */
    protected function useDiskAnchor(): DiskAnchor
    {
        $anchor = new DiskAnchor(Storage::fake(self::ANCHOR_DISK), self::ANCHOR_DISK, self::ANCHOR_PATH, app(SealSettings::class)->logId());

        app()->instance(CheckpointAnchor::class, $anchor);

        return $anchor;
    }

    /**
     * Store and seal the number of seals, each of the number of entries, the
     * entries of each next seal recorded a minute after those before, and
     * return the stored seals.
     *
     * @param  int  $seals
     * @param  int  $entries
     * @return list<array<string, scalar|null>>
     */
    protected function sealLog(int $seals, int $entries = 2): array
    {
        $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');

        for ($seal = 0; $seal < $seals; $seal++) {
            $this->storeEntries($entries, $first->addMinutes($seal)->format('Y-m-d H:i:s.u'));
            $this->sealAll();
        }

        return $this->seals();
    }

    /**
     * Change the stored entry's columns to the values given.
     *
     * @param  string  $id
     * @param  array<string, scalar|null>  $columns
     * @return void
     */
    protected function editEntry(string $id, array $columns): void
    {
        $this->tamperedTable(EntrySettings::table())->where('id', $id)->update($columns);
    }

    /**
     * Insert a copy of the stored entry under the columns given, which name its
     * new id, as a writer could fabricate a row, and return the new id.
     *
     * @param  string  $id
     * @param  array<string, scalar|null>&array{id: string}  $columns
     * @return string
     */
    protected function copyEntry(string $id, array $columns): string
    {
        $stored = (array) $this->tamperedTable(EntrySettings::table())->where('id', $id)->first();

        $this->tamperedTable(EntrySettings::table())->insert(array_replace($stored, $columns));

        return $columns['id'];
    }

    /**
     * Change the columns of the stored seal at the sequence to the values
     * given, leaving its digest and signature as they are.
     *
     * @param  int  $sequence
     * @param  array<string, scalar|null>  $columns
     * @return void
     */
    protected function editSeal(int $sequence, array $columns): void
    {
        $this->tamperedTable(IntegrityTables::checkpointsTable())->where('sequence', $sequence)->update($columns);
    }

    /**
     * Rewrite the envelope fields of the stored seal at the sequence and store
     * the digest of the result, keeping its signature, as anyone without the
     * key could, and return the new digest.
     *
     * @param  int  $sequence
     * @param  array<string, scalar|null>  $fields
     * @return string
     */
    protected function rewriteSeal(int $sequence, array $fields): string
    {
        $envelope = $this->rewrittenEnvelope($sequence, $fields);
        $digest   = $envelope->digest();

        $this->editSeal($envelope->sequence, ['seal_digest' => $digest]);

        return $digest;
    }

    /**
     * Rewrite the envelope fields of the stored seal at the sequence, then
     * store the digest of the result and its signature under the key ring's key
     * the seal names, as anyone holding the key could, and return the new
     * digest.
     *
     * @param  int  $sequence
     * @param  array<string, scalar|null>  $fields
     * @return string
     */
    protected function forgeSeal(int $sequence, array $fields): string
    {
        $envelope = $this->rewrittenEnvelope($sequence, $fields);
        $digest   = $envelope->digest();

        $this->editSeal($envelope->sequence, ['seal_digest' => $digest, 'signature' => app(SealSigner::class)->sign($envelope)]);

        return $digest;
    }

    /**
     * The member count and members digest of the member rows the seal at the
     * sequence now has, as a rewrite of its envelope states them.
     *
     * @param  int  $sequence
     * @return array{member_count: int, members_digest: string}
     */
    protected function membershipOf(int $sequence): array
    {
        /** @var list<object{entry_id: string, hmac: string}&\stdClass> $members */
        $members = $this->tamperedTable(IntegrityTables::membersTable())->where('checkpoint_id', $this->sealIdAt($sequence))->get(['entry_id', 'hmac'])->all();
        $pairs   = array_map(static fn (object $member): array => [$member->entry_id, $member->hmac], $members);

        return ['member_count' => count($pairs), 'members_digest' => SealEnvelope::membersDigest($pairs)];
    }

    /**
     * Delete the stored seal at the sequence and, when asked, its member rows
     * and their entries with it, so nothing of it is left.
     *
     * @param  int  $sequence
     * @param  bool  $withMembers
     * @return void
     */
    protected function deleteSeal(int $sequence, bool $withMembers): void
    {
        $id = $this->sealIdAt($sequence);

        if ($withMembers) {
            $this->tamperedTable(EntrySettings::table())->whereIn('id', $this->membersOf($id))->delete();
            $this->tamperedTable(IntegrityTables::membersTable())->where('checkpoint_id', $id)->delete();
        }

        $this->tamperedTable(IntegrityTables::checkpointsTable())->where('id', $id)->delete();
    }

    /**
     * Add a member row for the entry to the seal at the sequence, recording the
     * entry's own HMAC, as the seal would hold it had it sealed the entry.
     *
     * @param  int  $sequence
     * @param  string  $entryId
     * @return void
     */
    protected function addMember(int $sequence, string $entryId): void
    {
        $hmac = $this->tamperedTable(EntrySettings::table())->where('id', $entryId)->value('hmac');

        $this->tamperedTable(IntegrityTables::membersTable())->insert(['checkpoint_id' => $this->sealIdAt($sequence), 'entry_id' => $entryId, 'hmac' => $hmac]);
    }

    /**
     * Delete the member row of the entry, leaving the entry and its seal.
     *
     * @param  string  $entryId
     * @return void
     */
    protected function deleteMember(string $entryId): void
    {
        $this->tamperedTable(IntegrityTables::membersTable())->where('entry_id', $entryId)->delete();
    }

    /**
     * Swap the first member, in entry id order, of the seal at one sequence
     * with the first member of the seal at the other, so each seal keeps its
     * count and every entry stays sealed once.
     *
     * @param  int  $a
     * @param  int  $b
     * @return void
     */
    protected function swapMembers(int $a, int $b): void
    {
        $first  = $this->sealIdAt($a);
        $second = $this->sealIdAt($b);
        $moving = [$this->membersOf($first)[0], $this->membersOf($second)[0]];

        $this->tamperedTable(IntegrityTables::membersTable())->where('entry_id', $moving[0])->update(['checkpoint_id' => $second]);
        $this->tamperedTable(IntegrityTables::membersTable())->where('entry_id', $moving[1])->update(['checkpoint_id' => $first]);
    }

    /**
     * Clear every seal's anchor columns, so no local receipt of any anchoring
     * is left.
     *
     * @return void
     */
    protected function clearReceipts(): void
    {
        $this->tamperedTable(IntegrityTables::checkpointsTable())->update(['anchor' => null, 'anchor_receipt' => null, 'anchored_at' => null, 'anchor_error_class' => null]);
    }

    /**
     * Run `audit-log:seal` and return its exit code and what it printed.
     *
     * @return array{0: int, 1: string}
     */
    protected function runSeal(): array
    {
        $kernel = app(Kernel::class);
        $exit   = $kernel->call('audit-log:seal');

        return [$exit, $kernel->output()];
    }

    /**
     * Run `audit-log:verify` with the options given and return its exit code
     * and what it printed.
     *
     * @param  array<string, bool|string>  $options
     * @return array{0: int, 1: string}
     */
    protected function verify(array $options = []): array
    {
        $kernel = app(Kernel::class);
        $exit   = $kernel->call('audit-log:verify', $options);

        return [$exit, $kernel->output()];
    }

    /**
     * The id of the stored seal at the sequence.
     *
     * @param  int  $sequence
     * @return string
     */
    protected function sealIdAt(int $sequence): string
    {
        $id = $this->tamperedTable(IntegrityTables::checkpointsTable())->where('sequence', $sequence)->value('id');

        assert(is_string($id), sprintf('No seal is stored at sequence %d.', $sequence));

        return $id;
    }

    /**
     * Rewrite the envelope fields of the stored seal at the sequence and return
     * its envelope as it is then stored.
     *
     * @param  int  $sequence
     * @param  array<string, scalar|null>  $fields
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     */
    private function rewrittenEnvelope(int $sequence, array $fields): SealEnvelope
    {
        $id = $this->sealIdAt($sequence);

        $this->tamperedTable(IntegrityTables::checkpointsTable())->where('id', $id)->update($fields);

        /** @var array<string, scalar|null> $stored */
        $stored = (array) $this->tamperedTable(IntegrityTables::checkpointsTable())->where('id', $fields['id'] ?? $id)->first();

        return SealEnvelope::fromRow($stored);
    }

    /**
     * A query of the table on the storage connection, below the package.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    private function tamperedTable(string $table): Builder
    {
        return DB::connection(StorageConnection::name())->table($table);
    }
}
