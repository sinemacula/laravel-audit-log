<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Classifies a chunk's lines as new, duplicates or conflicts by source identity
 * and the keyed digest of the source assertion; it never writes.
 *
 * The digest is taken before minimisation, so a definition changed between two
 * imports never turns a repeated line into a conflict.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportClassifier
{
    /** @var int Source record ids looked up by one statement. */
    public const int LOOKUP_IDS = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\SourceDigest  $digests
     */
    public function __construct(

        /** Digests the lines' assertions for comparison. */
        private SourceDigest $digests,
    ) {}

    /**
     * The digest of the line's source assertion under the ring's signing key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \UnexpectedValueException
     */
    public function digestOf(#[\SensitiveParameter] ImportLine $line): string
    {
        return $this->digests->of($line->assertion(), $this->digests->signingKeyId());
    }

    /**
     * The plan of the lines in file order.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \UnexpectedValueException
     */
    public function classify(Connection $connection, #[\SensitiveParameter] array $lines): ImportPlan
    {
        $keyId      = $this->digests->signingKeyId();
        $stored     = self::stored($connection, $lines);
        $candidates = [];
        $new        = [];
        $digests    = [];
        $duplicates = 0;
        $conflicts  = [];

        foreach ($lines as $line) {
            $identity = self::identityOf($line->sourceId, $line->sourceRecordId);
            $digest   = $this->digests->of($line->assertion(), $keyId);
            $known    = $stored[$identity] ?? $candidates[$identity] ?? null;

            if ($known === null) {
                $candidates[$identity]  = [$digest, $keyId];
                $new[]                  = $line;
                $digests[$line->number] = $digest;

                continue;
            }

            if ($this->isDuplicateOf($line, $digest, $keyId, $known)) {
                $duplicates++;

                continue;
            }

            $conflicts[$line->number] = $line->sourceRecordId;
        }

        return new ImportPlan($new, $digests, $duplicates, $conflicts);
    }

    /**
     * Whether the line's digest, under the known digest's key, matches it; an
     * unknown key or a missing digest is a conflict.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @param  string  $digest
     * @param  string  $keyId
     * @param  array{0: ?string, 1: ?string}  $known
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    private function isDuplicateOf(#[\SensitiveParameter] ImportLine $line, string $digest, string $keyId, array $known): bool
    {
        [$knownDigest, $knownKeyId] = $known;

        if ($knownDigest === null || $knownKeyId === null) {
            return false;
        }

        try {
            $comparable = $knownKeyId === $keyId ? $digest : $this->digests->of($line->assertion(), $knownKeyId);
        } catch (UnknownKeyException) {
            return false;
        }

        return hash_equals($knownDigest, $comparable);
    }

    /**
     * The digest and key of every stored row under the lines' identities.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @return array<string, array{0: ?string, 1: ?string}>
     *
     * @throws \UnexpectedValueException
     */
    private static function stored(Connection $connection, #[\SensitiveParameter] array $lines): array
    {
        $sources = [];

        // Prefixed so a numeric id never becomes an integer key or binding
        foreach ($lines as $line) {
            $sources['s:' . $line->sourceId]['source']                            = $line->sourceId;
            $sources['s:' . $line->sourceId]['ids']['r:' . $line->sourceRecordId] = $line->sourceRecordId;
        }

        $stored = [];

        foreach ($sources as ['source' => $sourceId, 'ids' => $recordIds]) {
            foreach (array_chunk(array_values($recordIds), self::LOOKUP_IDS) as $page) {
                $rows = $connection->table(EntrySettings::table())
                    ->useWritePdo()
                    ->where('source_id', $sourceId)
                    ->whereIn('source_record_id', $page)
                    ->get(['source_id', 'source_record_id', 'source_digest', 'key_id']);

                foreach ($rows as $row) {
                    $identity = self::identityOf(self::text($row->source_id) ?? '', self::text($row->source_record_id) ?? '');

                    $stored[$identity] = [self::text($row->source_digest), self::text($row->key_id)];
                }
            }
        }

        return $stored;
    }

    /**
     * The source identity as one key.
     *
     * @param  string  $sourceId
     * @param  string  $sourceRecordId
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function identityOf(string $sourceId, string $sourceRecordId): string
    {
        return CanonicalEncoder::encode([$sourceId, $sourceRecordId]);
    }

    /**
     * The stored value as text, or `null` when it is not a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    private static function text(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
