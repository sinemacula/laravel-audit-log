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
 * An anchor that writes each seal's summary to a filesystem disk once and never
 * replaces it. It is only as tamper-evident as the disk is write-once.
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

    /** @var string The refusal of a path that holds a partial write. */
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
     * disk's name and the path.
     *
     * @return string
     */
    #[\Override]
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Write the marker, then the object, each only when not there yet; the
     * marker goes first so a conflict is one read, even after a crash.
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
     * The head: the highest marker whose object is there, or `null` for none. A
     * partial or malformed write throws instead of reading as absent.
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
     * The head at the sequence, or `null` when its marker or object is missing.
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
     * The highest sequence with a marker, or 0 for none. Markers run unbroken
     * from 1, so it probes doubling sequences, then bisects the gap.
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
     * Write the contents unless the path holds them. A different whole value is
     * a conflict; a partial one is another anchorer still writing.
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
     * The summary's canonical encoding.
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
