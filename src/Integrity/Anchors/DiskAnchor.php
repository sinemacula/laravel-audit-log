<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Anchors;

use Illuminate\Contracts\Filesystem\Filesystem;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * An anchor that keeps each seal's summary as a file on a filesystem disk,
 * written once and never replaced.
 *
 * Each summary is written in its canonical encoding to
 * `{path}/{log_id}/{sequence}-{seal_digest}.json`, the sequence padded to 20
 * digits, after a marker at `{path}/{log_id}/by-sequence/{sequence}` that holds
 * the digest. The marker comes first, so another digest for a sequence is found
 * with one read, even after a crash between the two writes; the next anchoring
 * of the same summary completes the object. A path that exists is read and
 * compared, never written again, and nothing is ever deleted, so anchoring is
 * idempotent and two digests for one sequence are a conflict. A path that holds
 * a partial write, one another anchorer is still making, is read as an anchor
 * unavailable for now, never as a conflict: only a whole marker or summary that
 * differs is one. The receipt is the object's path and the SHA-256 of its
 * bytes. The anchor holds one log, the one it is made for, and refuses a
 * summary of another, so no path ever leaves `{path}/{log_id}`.
 *
 * Discovery reads the markers, which are authoritative: the anchorer writes
 * them in sequence order from 1 and stops at its first failure, so they run
 * unbroken from 1 to the head. The highest is found by probing whether markers
 * exist at doubling sequences and then halving the gap, in about two existence
 * checks per doubling of the log, with memory that does not grow with the log,
 * and the head is the highest marker whose object is there.
 *
 * Its guarantees are conditional on the disk itself refusing to replace or
 * delete what was written (S3 Object Lock in compliance mode with a retention
 * period and a bucket policy denying version deletion, or an equivalent write
 * once store): a disk the application can overwrite is evidence only against
 * someone who cannot reach it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DiskAnchor implements CheckpointAnchor
{
    /** @var string The refusal of a newest object that is not a seal's summary. */
    private const string MALFORMED = 'The anchor\'s newest object is malformed.';

    /** @var string The refusal of a path that holds a partial write, which the next run reads again. */
    private const string PARTIAL = 'The anchor holds a partial write; it is read again on the next run.';

    /** @var string The anchor's name: its location, so moving it anchors every seal again. */
    private string $name;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @param  string  $diskName
     * @param  string  $path
     * @param  string  $logId
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The disk the summaries are written to. */
        private Filesystem $disk,

        // The name of that disk, which the anchor's name is made from.
        string $diskName,

        /** The namespace on the disk the summaries are written under. */
        private string $path,

        /** The log the anchor holds. */
        private string $logId,
    ) {
        if (!AnchorSettings::isContainedPath($path)) {
            $message = 'A disk anchor\'s path must be 1 to 191 characters of path segments of letters, digits, dots, underscores'
                . ' and hyphens, separated by single slashes, with no `.` or `..` segment.';

            throw new \InvalidArgumentException($message);
        }

        if (preg_match(SealEnvelope::LOG_ID_PATTERN, $logId) !== 1) {
            throw new \InvalidArgumentException('A disk anchor\'s log id must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        $this->name = 'disk:' . substr(hash('sha256', $diskName . "\0" . $path), 0, 16);
    }

    /**
     * The anchor's name: `disk:` and the first 16 hex of the SHA-256 of the
     * disk's name and the path, so one location always has one name and another
     * location another.
     *
     * @return string
     */
    #[\Override]
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Write the summary's marker, then its object, each only when it is not
     * there yet, and return the object's path and the SHA-256 of its bytes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return array{path: string, sha256: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function anchor(SealSummary $seal): array
    {
        $object = $this->pathOf($seal);
        $bytes  = self::bytesOf($seal);

        $this->writeOnce($this->markerAt($seal->sequence), $seal->sealDigest, $seal->sequence, self::isDigest(...));
        $this->writeOnce($object, $bytes, $seal->sequence, fn (string $held): bool => $this->isSummaryOf($held, $seal->sequence, $seal->sealDigest));

        return ['path' => $object, 'sha256' => hash('sha256', $bytes)];
    }

    /**
     * Whether the receipt is exactly the path and hash this anchor gives for
     * the summary, and the object there holds exactly the summary's bytes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @param  array<string, scalar|null>  $receipt
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function confirms(SealSummary $seal, array $receipt): bool
    {
        $object = $this->pathOf($seal);
        $bytes  = self::bytesOf($seal);

        if (count($receipt) !== 2 || ($receipt['path'] ?? null) !== $object || ($receipt['sha256'] ?? null) !== hash('sha256', $bytes)) {
            return false;
        }

        return $this->read($object) === $bytes;
    }

    /**
     * Whether the anchor can report its head: it can, from its markers.
     *
     * @return bool
     */
    #[\Override]
    public function supportsDiscovery(): bool
    {
        return true;
    }

    /**
     * The highest sequence the anchor holds and its digest, or `null` when the
     * log has none: the highest marker whose object is there, so a marker a
     * crash left without its object is never the head and the one before it is.
     * A marker that is not a digest is a partial write, and an object whose
     * bytes are not the canonical summary of its sequence and digest in this
     * log is malformed; each fails, never reads as an absence.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function latest(): ?AnchoredHead
    {
        $highest = $this->highestMarker();

        if ($highest === 0) {
            return null;
        }

        $head = $this->headAt($highest);

        if ($head !== null || $highest === 1) {
            return $head;
        }

        return $this->headAt($highest - 1) ?? throw new \UnexpectedValueException(self::MALFORMED);
    }

    /**
     * The path of the summary's object on the disk.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public function pathOf(SealSummary $seal): string
    {
        if ($seal->logId !== $this->logId) {
            throw new \InvalidArgumentException('A disk anchor holds one log; the seal names another.');
        }

        return $this->objectAt($seal->sequence, $seal->sealDigest);
    }

    /**
     * The head at the sequence, from its marker, or `null` when the marker's
     * object is not there; a marker that is not a digest is a partial write,
     * and an object that is not the canonical summary is malformed.
     *
     * @param  int  $sequence
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \UnexpectedValueException
     */
    private function headAt(int $sequence): ?AnchoredHead
    {
        $digest = $this->read($this->markerAt($sequence));

        if ($digest === null) {
            return null;
        }

        if (!self::isDigest($digest)) {
            throw new \UnexpectedValueException(self::PARTIAL);
        }

        $bytes = $this->read($this->objectAt($sequence, $digest));

        if ($bytes === null) {
            return null;
        }

        if (!$this->isSummaryOf($bytes, $sequence, $digest)) {
            throw new \UnexpectedValueException(self::MALFORMED);
        }

        return new AnchoredHead($sequence, $digest);
    }

    /**
     * The highest sequence that has a marker, or 0 when none has: markers are
     * probed at 1 and then at doubling sequences until one is missing, and the
     * gap between the last there and the first missing is then halved until it
     * closes.
     *
     * @return int
     */
    private function highestMarker(): int
    {
        [$there, $missing] = [0, 1];

        while ($this->hasMarker($missing)) {
            if ($missing === PHP_INT_MAX) {
                return PHP_INT_MAX;
            }

            [$there, $missing] = [$missing, $missing > intdiv(PHP_INT_MAX, 2) ? PHP_INT_MAX : $missing << 1];
        }

        while ($missing - $there > 1) {
            $middle = $there + intdiv($missing - $there, 2);

            [$there, $missing] = $this->hasMarker($middle) ? [$middle, $missing] : [$there, $middle];
        }

        return $there;
    }

    /**
     * Whether a marker is written at the sequence.
     *
     * @param  int  $sequence
     * @return bool
     */
    private function hasMarker(int $sequence): bool
    {
        return $this->disk->exists($this->markerAt($sequence));
    }

    /**
     * Whether the bytes are exactly the canonical summary of the sequence and
     * digest in this log, under the seal id they name.
     *
     * @param  string  $bytes
     * @param  int  $sequence
     * @param  string  $digest
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function isSummaryOf(string $bytes, int $sequence, string $digest): bool
    {
        $decoded = json_decode($bytes, true);
        $sealId  = is_array($decoded) ? ($decoded['seal_id'] ?? null) : null;

        if (!is_string($sealId) || preg_match(SealEnvelope::UUID_PATTERN, $sealId) !== 1) {
            return false;
        }

        return self::bytesOf(new SealSummary($this->logId, $sequence, $sealId, $digest)) === $bytes;
    }

    /**
     * Write the contents to the path when nothing is there; when the path
     * already holds exactly the contents, write nothing. When it holds a whole
     * marker or summary that differs, the anchor holds another digest for the
     * sequence; when what it holds is not whole, another anchorer is still
     * writing it, and the anchor is unavailable for now.
     *
     * @param  string  $path
     * @param  string  $contents
     * @param  int  $sequence
     * @param  \Closure(string): bool  $isWhole
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     * @throws \UnexpectedValueException
     */
    private function writeOnce(string $path, string $contents, int $sequence, \Closure $isWhole): void
    {
        $held = $this->read($path);

        if ($held === $contents) {
            return;
        }

        if ($held !== null && $isWhole($held)) {
            throw AnchorConflictException::forSequence($sequence);
        }

        if ($held !== null) {
            throw new \UnexpectedValueException(self::PARTIAL);
        }

        if (!$this->disk->put($path, $contents)) {
            throw new \UnexpectedValueException('The anchor could not write to its disk.');
        }
    }

    /**
     * The bytes at the path, or `null` when nothing is there; a path that is
     * there and cannot be read is a failure, never an absence.
     *
     * @param  string  $path
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    private function read(string $path): ?string
    {
        if (!$this->disk->exists($path)) {
            return null;
        }

        return $this->disk->get($path) ?? throw new \UnexpectedValueException('The anchor could not read its disk.');
    }

    /**
     * The path of the object that holds the summary of the sequence and digest.
     *
     * @param  int  $sequence
     * @param  string  $digest
     * @return string
     */
    private function objectAt(int $sequence, string $digest): string
    {
        return sprintf('%s/%s/%020d-%s.json', $this->path, $this->logId, $sequence, $digest);
    }

    /**
     * The path of the marker that holds the digest anchored at the sequence.
     *
     * @param  int  $sequence
     * @return string
     */
    private function markerAt(int $sequence): string
    {
        return sprintf('%s/%s/by-sequence/%020d', $this->path, $this->logId, $sequence);
    }

    /**
     * The bytes of the summary's object: its canonical encoding.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function bytesOf(SealSummary $seal): string
    {
        return CanonicalEncoder::encode($seal->toArray());
    }

    /**
     * Whether the value is a digest: 64 lower-case hex.
     *
     * @param  string  $value
     * @return bool
     */
    private static function isDigest(string $value): bool
    {
        return preg_match(SealEnvelope::DIGEST_PATTERN, $value) === 1;
    }
}
