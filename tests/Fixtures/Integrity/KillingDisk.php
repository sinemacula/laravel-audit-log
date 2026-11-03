<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Integrity;

use Illuminate\Contracts\Filesystem\Filesystem;

/**
 * A disk that hands every call to another and ends the process by `SIGKILL`
 * straight after the number of writes it is made with have succeeded: the last
 * write is on the disk, and nothing the caller would have done next is. It
 * reaches the gap between two writes of one call, which a decorated anchor
 * cannot reach from outside, such as a disk anchor's marker and its object. A
 * write that fails is not counted. It is for the children of the crash tests
 * only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KillingDisk implements Filesystem
{
    /** @var \ArrayObject<int, string> The paths written so far, in order. */
    private \ArrayObject $written;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Filesystem\Filesystem  $disk
     * @param  int  $writes
     */
    public function __construct(

        /** The disk every call is handed to. */
        private Filesystem $disk,

        /** How many writes succeed before the process dies, straight after the last of them. */
        private int $writes,
    ) {
        $this->written = new \ArrayObject;
    }

    // The contract declares its parameters untyped, and PHP refuses a native
    // type that narrows one, so each is typed by its docblock alone
    // phpcs:disable Squiz.Commenting.FunctionComment.ScalarTypeHintMissing

    /**
     * The full path of the file at the path.
     *
     * @param  string  $path
     * @return string
     */
    #[\Override]
    public function path($path): string
    {
        return $this->disk->path($path);
    }

    /**
     * Whether a file is at the path.
     *
     * @param  string  $path
     * @return bool
     */
    #[\Override]
    public function exists($path): bool
    {
        return $this->disk->exists($path);
    }

    /**
     * The contents of the file at the path, or `null` when it cannot be read.
     *
     * @param  string  $path
     * @return ?string
     */
    #[\Override]
    public function get($path): ?string
    {
        return $this->disk->get($path);
    }

    /**
     * A stream that reads the file at the path, or `null` when it cannot be
     * opened.
     *
     * @param  string  $path
     * @return resource|null
     */
    #[\Override]
    public function readStream($path)
    {
        return $this->disk->readStream($path);
    }

    /**
     * Write the contents to the path, and die straight after the last write the
     * disk is made to let succeed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @param  \Illuminate\Http\File|\Illuminate\Http\UploadedFile|\Psr\Http\Message\StreamInterface|resource|string  $contents
     * @param  mixed  $options
     * @return bool
     */
    #[\Override]
    public function put($path, $contents, mixed $options = [])
    {
        if ($this->disk->put($path, $contents, $options) === false) {
            return false;
        }

        $this->written->append($path);

        if ($this->written->count() >= $this->writes) {
            self::killThisProcess();
        }

        return true;
    }

    /**
     * Store the file on the disk under the path, never counted as a write.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Http\File|\Illuminate\Http\UploadedFile|string  $path
     * @param  array<array-key, mixed>|\Illuminate\Http\File|\Illuminate\Http\UploadedFile|string|null  $file
     * @param  mixed  $options
     * @return false|string
     */
    #[\Override]
    public function putFile($path, $file = null, mixed $options = []): false|string
    {
        return $this->disk->putFile($path, $file, $options);
    }

    /**
     * Store the file on the disk under the path and the name, never counted as
     * a write.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Http\File|\Illuminate\Http\UploadedFile|string  $path
     * @param  array<array-key, mixed>|\Illuminate\Http\File|\Illuminate\Http\UploadedFile|string|null  $file
     * @param  array<array-key, mixed>|string|null  $name
     * @param  mixed  $options
     * @return false|string
     */
    #[\Override]
    public function putFileAs($path, $file, $name = null, mixed $options = []): false|string
    {
        return $this->disk->putFileAs($path, $file, $name, $options);
    }

    /**
     * Write the stream to the path, never counted as a write.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @param  resource  $resource
     * @param  array<array-key, mixed>  $options
     * @return bool
     */
    #[\Override]
    public function writeStream($path, $resource, array $options = []): bool
    {
        return $this->disk->writeStream($path, $resource, $options);
    }

    /**
     * The visibility of the file at the path.
     *
     * @param  string  $path
     * @return string
     */
    #[\Override]
    public function getVisibility($path): string
    {
        return $this->disk->getVisibility($path);
    }

    /**
     * Set the visibility of the file at the path.
     *
     * @param  string  $path
     * @param  string  $visibility
     * @return bool
     */
    #[\Override]
    public function setVisibility($path, $visibility)
    {
        return $this->disk->setVisibility($path, $visibility);
    }

    /**
     * Prepend the data to the file at the path, never counted as a write.
     *
     * @param  string  $path
     * @param  string  $data
     * @return bool
     */
    #[\Override]
    public function prepend($path, $data)
    {
        return $this->disk->prepend($path, $data);
    }

    /**
     * Append the data to the file at the path, never counted as a write.
     *
     * @param  string  $path
     * @param  string  $data
     * @return bool
     */
    #[\Override]
    public function append($path, $data)
    {
        return $this->disk->append($path, $data);
    }

    /**
     * Delete the file at each path.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|string  $paths
     * @return bool
     */
    #[\Override]
    public function delete($paths): bool
    {
        return $this->disk->delete($paths);
    }

    /**
     * Copy the file to another path.
     *
     * @param  string  $from
     * @param  string  $to
     * @return bool
     */
    #[\Override]
    public function copy($from, $to)
    {
        return $this->disk->copy($from, $to);
    }

    /**
     * Move the file to another path.
     *
     * @param  string  $from
     * @param  string  $to
     * @return bool
     */
    #[\Override]
    public function move($from, $to)
    {
        return $this->disk->move($from, $to);
    }

    /**
     * The size of the file at the path, in bytes.
     *
     * @param  string  $path
     * @return int
     */
    #[\Override]
    public function size($path): int
    {
        return $this->disk->size($path);
    }

    /**
     * When the file at the path was last modified, as a Unix time.
     *
     * @param  string  $path
     * @return int
     */
    #[\Override]
    public function lastModified($path): int
    {
        return $this->disk->lastModified($path);
    }

    /**
     * The files in the directory, and in those below it when recursive.
     *
     * @param  ?string  $directory
     * @param  bool  $recursive
     * @return array<string>
     */
    #[\Override]
    public function files($directory = null, $recursive = false): array
    {
        return $this->disk->files($directory, $recursive);
    }

    /**
     * The files in the directory and in every directory below it.
     *
     * @param  ?string  $directory
     * @return array<string>
     */
    #[\Override]
    public function allFiles($directory = null): array
    {
        return $this->disk->allFiles($directory);
    }

    /**
     * The directories in the directory, and in those below it when recursive.
     *
     * @param  ?string  $directory
     * @param  bool  $recursive
     * @return array<string>
     */
    #[\Override]
    public function directories($directory = null, $recursive = false): array
    {
        return $this->disk->directories($directory, $recursive);
    }

    /**
     * The directories in the directory and in every directory below it.
     *
     * @param  ?string  $directory
     * @return array<string>
     */
    #[\Override]
    public function allDirectories($directory = null): array
    {
        return $this->disk->allDirectories($directory);
    }

    /**
     * Make a directory at the path.
     *
     * @param  string  $path
     * @return bool
     */
    #[\Override]
    public function makeDirectory($path): bool
    {
        return $this->disk->makeDirectory($path);
    }

    /**
     * Delete the directory and everything in it.
     *
     * @param  string  $directory
     * @return bool
     */
    #[\Override]
    public function deleteDirectory($directory): bool
    {
        return $this->disk->deleteDirectory($directory);
    }

    // phpcs:enable Squiz.Commenting.FunctionComment.ScalarTypeHintMissing

    /**
     * End this process by `SIGKILL`, which nothing can handle or delay.
     *
     * @return never
     */
    private static function killThisProcess(): never
    {
        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
