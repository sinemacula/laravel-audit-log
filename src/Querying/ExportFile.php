<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Support\Str;

/**
 * The file an export is written to, from the moment it is prepared to the
 * moment it is published: a temporary file beside the target, its digests and
 * positions kept as each line is written, a temporary bundle beside it, and the
 * publication of both.
 *
 * Each temporary file is `.<name>.<uuid>.tmp` in the target's directory,
 * created exclusively under a umask of `0077`, restored at once, then made
 * `0600`, so no other user can open it at any moment, before its first byte or
 * after. Every line, the last included, ends in one line feed, so an export of
 * no line is an empty file. The file's digest is the SHA-256 of its bytes, its
 * membership digest the SHA-256 of each id and a line feed in file order, and
 * its first and last positions are the recorded instant and id of its first and
 * last lines. The file is closed when the bundle is written, and takes no line
 * after it.
 *
 * Publication puts the bundle at `<target>.manifest.json`, then the file at the
 * target. Without `force` each is hard-linked to its place and its temporary
 * file unlinked, which fails, never replaces, when the place is taken, even by
 * a file that appeared after the export was prepared; a directory whose
 * filesystem cannot hold a hard link is refused before anything is made, so an
 * export that could never be published is never journalled. With `force` the
 * file already at each place is first renamed aside, beside it, a directory
 * refused, then the new one is renamed into the place, and only once both are
 * in place are the set-aside files removed. A step that fails removes both
 * temporary files and whatever this publication had already put in place,
 * renames back what it had set aside, so a previous export and its bundle are
 * left as they were, then throws naming the step alone.
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

    /** @var string What the name of a file set aside by a forced publication ends in. */
    private const string ASIDE_SUFFIX = '.replaced';

    /** @var string What the names of the hard-link probe's files end in. */
    private const string PROBE_SUFFIX = '.probe';

    /** @var int The umask a temporary file is created under: nothing for the group or anyone else. */
    private const int UMASK = 0077;

    /** @var int The mode of a temporary file, and so of a published one: read and write for its owner alone. */
    private const int MODE = 0600;

    /** @var ?resource The temporary file, open for writing until the bundle is written. */
    private mixed $handle;

    /** @var \HashContext The running SHA-256 of the file's bytes. */
    private \HashContext $file;

    /** @var \SineMacula\Laravel\AuditLog\Querying\MembershipDigest The running digest of the ids written, in file order. */
    private MembershipDigest $membership;

    /** @var int How many lines have been written. */
    private int $lines = 0;

    /** @var ?array{0: string, 1: string} The recorded instant and id of the first line, once there is one. */
    private ?array $first = null;

    /** @var ?array{0: string, 1: string} The recorded instant and id of the last line, once there is one. */
    private ?array $last = null;

    /** @var ?string The temporary bundle, once it is created and until it is published or removed. */
    private ?string $bundleTemp = null;

    /** @var bool Whether both temporary files have been published or removed, so neither is touched again. */
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
     * Prepare an export to the target: refuse a directory that does not exist
     * or is not writable, a target that is a directory, and a target or bundle
     * that exists without `force`, then create the temporary file.
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
     * Refuse a target whose directory does not exist or is not writable, a
     * target that is a directory, and, without `force`, a target or a bundle
     * that exists, or a directory whose filesystem cannot hold the hard link a
     * publication without `force` needs: the checks `prepare()` makes before it
     * creates anything, so an export can make them before anything else. The
     * hard-link probe leaves nothing behind.
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
     * Append a line and a line feed, and keep the digests, the count and the
     * positions of the entry it holds.
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
     * The SHA-256 of the bytes written so far, as 64 lower-case hexadecimal
     * characters.
     *
     * @return string
     */
    public function fileSha256(): string
    {
        return hash_final(hash_copy($this->file));
    }

    /**
     * The membership digest of the ids written, in file order. It is taken
     * once, so no line is written after it.
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
     * Close the file, which takes no line after it, then write the bundle to a
     * temporary file of its own beside the target, created as the file's was.
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
     * Publish the bundle at `<target>.manifest.json`, then the file at the
     * target: linked into place without `force`, so neither replaces what is
     * there, and with `force` renamed into place once what is there is set
     * aside, which is removed only once both are in place. A step that fails
     * removes both temporary files and what this call had put in place, puts
     * back what it had set aside, then throws.
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
     * Remove both temporary files, leaving anything already published; once
     * removed, or published, nothing is removed again.
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
     * Undo a publication that failed: remove both temporary files and what it
     * had put in place, then rename what it had set aside back into place.
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
     * Whether the place is free once what is there is renamed aside, beside it,
     * where it went kept by the place: nothing there is free already, and a
     * directory, or a file that cannot be moved, never frees it.
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
     * Whether the target's directory can hold a hard link: a probe file is
     * created there exclusively under a name of its own and linked to a second
     * name, and whatever the probe made is removed, never anything else.
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
     * A temporary file's path for the place: hidden, in the place's directory,
     * named after it and made unique.
     *
     * @param  string  $place
     * @return string
     */
    private static function tempFor(string $place): string
    {
        return sprintf('%s/.%s.%s.tmp', dirname($place), basename($place), Str::uuid7()->toString());
    }

    /**
     * Create the temporary file exclusively under the umask, which is restored
     * however the open ends, then make it readable and writable by its owner
     * alone, and return it open for writing. A file already at the path is
     * never opened.
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
     * Put the temporary file in its place, saying whether it is there: linked,
     * failing when the place is taken, then unlinked, without `force`; renamed
     * over the place with it. A link whose temporary file cannot be unlinked is
     * taken back.
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
