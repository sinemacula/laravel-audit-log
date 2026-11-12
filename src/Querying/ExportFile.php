<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Support\Str;

/**
 * An export's file and bundle, written to private temporary files beside the
 * target and published together or not at all.
 *
 * Without `force`, publication hard-links into place so it never replaces a
 * file that appeared after the export was prepared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExportFile
{
    /** @var string What a bundle's path adds to its export's. */
    public const string MANIFEST_SUFFIX = '.manifest.json';

    /** @var string The suffix of a file set aside by a forced publication. */
    private const string ASIDE_SUFFIX = '.replaced';

    /** @var string The suffix of the hard-link probe's files. */
    private const string PROBE_SUFFIX = '.probe';

    /** @var int Created under this umask so no other user can ever open it. */
    private const int UMASK = 0077;

    /** @var int The mode of a temporary, and so a published, file. */
    private const int MODE = 0600;

    /** @var ?resource The temporary file, open for writing until the bundle is written. */
    private mixed $handle;

    /** @var \HashContext The running SHA-256 of the file's bytes. */
    private \HashContext $file;

    /** @var \SineMacula\Laravel\AuditLog\Querying\MembershipDigest The running digest of the ids written. */
    private MembershipDigest $membership;

    /** @var int How many lines have been written. */
    private int $lines = 0;

    /** @var ?array{0: string, 1: string} The recorded instant and id of the first line. */
    private ?array $first = null;

    /** @var ?array{0: string, 1: string} The recorded instant and id of the last line. */
    private ?array $last = null;

    /** @var ?string The temporary bundle, until it is published or removed. */
    private ?string $bundleTemp = null;

    /** @var bool Whether both temporary files have been published or removed. */
    private bool $finished = false;

    /**
     * Constructor.
     *
     * @param  string  $target
     * @param  string  $temp
     *
     * @throws \UnexpectedValueException
     */
    private function __construct(

        /** Where the file is published. */
        private readonly string $target,

        /** The temporary file the lines are written to, created here. */
        private readonly string $temp,
    ) {
        $this->handle     = self::create($temp);
        $this->file       = hash_init('sha256');
        $this->membership = new MembershipDigest;
    }

    /**
     * Check the target, then create the temporary file.
     *
     * @param  string  $target
     * @param  bool  $force
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public static function prepare(string $target, bool $force): self
    {
        self::check($target, $force);

        return new self($target, self::tempFor($target));
    }

    /**
     * Refuse a target that could never be published, before anything is made or
     * journalled.
     *
     * @param  string  $target
     * @param  bool  $force
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function check(string $target, bool $force): void
    {
        $directory = dirname($target);

        if (!is_dir($directory) || !is_writable($directory)) {
            throw new \InvalidArgumentException('The export target\'s directory does not exist or is not writable.');
        }

        if (is_dir($target)) {
            throw new \InvalidArgumentException('The export target is a directory.');
        }

        if ($force) {
            return;
        }

        if (self::isTaken($target) || self::isTaken($target . self::MANIFEST_SUFFIX)) {
            throw new \InvalidArgumentException('The export target already exists; pass force to replace it.');
        }

        if (!self::canLinkIn($target)) {
            throw new \InvalidArgumentException('The export target\'s filesystem cannot hold a hard link, so it cannot be published without force.');
        }
    }

    /**
     * Append a line and a line feed, updating the digests, count and positions.
     *
     * @param  string  $line
     * @param  string  $id
     * @param  string  $recordedAt
     * @return void
     *
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function write(#[\SensitiveParameter] string $line, string $id, string $recordedAt): void
    {
        if (!is_resource($this->handle)) {
            throw new \LogicException('An export takes no line once its file is closed.');
        }

        $this->membership->add($id);

        if (fwrite($this->handle, $line . "\n") !== strlen($line) + 1) {
            throw new \UnexpectedValueException('The export\'s temporary file could not be written.');
        }

        hash_update($this->file, $line . "\n");

        $this->lines++;
        $this->first ??= [$recordedAt, $id];
        $this->last = [$recordedAt, $id];
    }

    /**
     * How many lines have been written.
     *
     * @return int
     */
    public function lines(): int
    {
        return $this->lines;
    }

    /**
     * The hex SHA-256 of the bytes written so far.
     *
     * @return string
     */
    public function fileSha256(): string
    {
        return hash_final(hash_copy($this->file));
    }

    /**
     * The membership digest of the ids written; take it after the last line.
     *
     * @return string
     */
    public function membershipSha256(): string
    {
        return $this->membership->digest();
    }

    /**
     * The recorded instant and id of the first line, or `null` with none.
     *
     * @return ?array{0: string, 1: string}
     */
    public function first(): ?array
    {
        return $this->first;
    }

    /**
     * The recorded instant and id of the last line, or `null` with none.
     *
     * @return ?array{0: string, 1: string}
     */
    public function last(): ?array
    {
        return $this->last;
    }

    /**
     * Close the file, then write the bundle to its own temporary file.
     *
     * @param  string  $bundle
     * @return void
     *
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function writeBundle(#[\SensitiveParameter] string $bundle): void
    {
        if ($this->finished || !is_resource($this->handle)) {
            throw new \LogicException('An export\'s bundle is written once, before it is published.');
        }

        $flushed = fflush($this->handle);
        $closed  = fclose($this->handle);

        $this->handle = null;

        if (!$flushed || !$closed) {
            throw new \UnexpectedValueException('The export\'s temporary file could not be written.');
        }

        $temp   = self::tempFor($this->target . self::MANIFEST_SUFFIX);
        $handle = self::create($temp);

        $this->bundleTemp = $temp;

        $written = fwrite($handle, $bundle) === strlen($bundle) && fflush($handle);

        if (!fclose($handle) || !$written) {
            throw new \UnexpectedValueException('The export\'s bundle could not be written.');
        }
    }

    /**
     * Publish the bundle, then the file; a failed step undoes both and leaves
     * any previous export as it was.
     *
     * @param  bool  $force
     * @return void
     *
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function publish(bool $force): void
    {
        if ($this->finished || $this->bundleTemp === null) {
            throw new \LogicException('An export is published once, with its bundle written.');
        }

        $steps = [
            'bundle' => [$this->bundleTemp, $this->target . self::MANIFEST_SUFFIX],
            'file'   => [$this->temp, $this->target],
        ];

        $placed = [];
        $asides = [];

        foreach ($steps as $step => [$temp, $place]) {
            if (($force && !self::frees($place, $asides)) || !self::place($temp, $place, $force)) {
                $this->undo($placed, $asides);

                throw new \UnexpectedValueException(sprintf('The export\'s %s could not be published.', $step));
            }

            $placed[] = $place;
        }

        array_map(self::remove(...), $asides);

        $this->finished = true;
    }

    /**
     * Remove both temporary files, leaving anything already published.
     *
     * @return void
     */
    public function discard(): void
    {
        if ($this->finished) {
            return;
        }

        if (is_resource($this->handle)) {
            fclose($this->handle);
        }

        $this->handle   = null;
        $this->finished = true;

        foreach (array_filter([$this->temp, $this->bundleTemp], static fn (?string $temp): bool => $temp !== null) as $temp) {
            self::remove($temp);
        }
    }

    /**
     * Remove what a failed publication placed and restore what it set aside.
     *
     * @param  list<string>  $placed
     * @param  array<string, string>  $asides
     * @return void
     */
    private function undo(array $placed, array $asides): void
    {
        $this->discard();

        foreach ($placed as $place) {
            self::remove($place);
        }

        foreach ($asides as $place => $aside) {
            @rename($aside, $place);
        }
    }

    /**
     * Whether the place is free once what is there is renamed aside; a
     * directory never frees it.
     *
     * @param  string  $place
     * @param  array<string, string>  $asides
     * @return bool
     */
    private static function frees(string $place, array &$asides): bool
    {
        if (!self::isTaken($place)) {
            return true;
        }

        $aside = sprintf('%s/.%s.%s%s', dirname($place), basename($place), Str::uuid7()->toString(), self::ASIDE_SUFFIX);
        $moved = !(is_dir($place) && !is_link($place)) && @rename($place, $aside);

        if ($moved) {
            $asides[$place] = $aside;
        }

        return $moved;
    }

    /**
     * Whether the target's directory can hold a hard link, probing with files
     * of its own that it removes.
     *
     * @param  string  $target
     * @return bool
     */
    private static function canLinkIn(string $target): bool
    {
        $probe  = sprintf('%s/.%s.%s%s', dirname($target), basename($target), Str::uuid7()->toString(), self::PROBE_SUFFIX);
        $handle = @fopen($probe, 'xb');

        if ($handle === false) {
            return false;
        }

        fclose($handle);

        $linked = @link($probe, $probe . self::PROBE_SUFFIX);

        if ($linked) {
            @unlink($probe . self::PROBE_SUFFIX);
        }

        @unlink($probe);

        return $linked;
    }

    /**
     * A unique hidden temporary path beside the place.
     *
     * @param  string  $place
     * @return string
     */
    private static function tempFor(string $place): string
    {
        return sprintf('%s/.%s.%s.tmp', dirname($place), basename($place), Str::uuid7()->toString());
    }

    /**
     * Create the temporary file exclusively and privately, open for writing.
     *
     * @param  string  $temp
     * @return resource
     *
     * @throws \UnexpectedValueException
     */
    private static function create(string $temp): mixed
    {
        $umask = umask(self::UMASK);

        try {
            $handle = @fopen($temp, 'xb');
        } finally {
            umask($umask);
        }

        if ($handle === false) {
            throw new \UnexpectedValueException('The export\'s temporary file could not be created.');
        }

        if (!chmod($temp, self::MODE)) {
            fclose($handle);
            self::remove($temp);

            throw new \UnexpectedValueException('The export\'s temporary file could not be made private.');
        }

        return $handle;
    }

    /**
     * Whether the temporary file was put in its place: renamed with `force`,
     * else linked, failing when the place is taken.
     *
     * @param  string  $temp
     * @param  string  $place
     * @param  bool  $force
     * @return bool
     *
     * @imperative
     */
    private static function place(string $temp, string $place, bool $force): bool
    {
        if ($force) {
            return @rename($temp, $place);
        }

        $linked = @link($temp, $place);

        if ($linked && !@unlink($temp)) {
            self::remove($place);

            return false;
        }

        return $linked;
    }

    /**
     * Whether something is at the path, a dangling link included.
     *
     * @param  string  $path
     * @return bool
     */
    private static function isTaken(string $path): bool
    {
        return file_exists($path) || is_link($path);
    }

    /**
     * Remove the file at the path, if there is one.
     *
     * @param  string  $path
     * @return void
     */
    private static function remove(string $path): void
    {
        if (!self::isTaken($path)) {
            return;
        }

        @unlink($path);
    }
}
