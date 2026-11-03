<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Anchors;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;

/**
 * The anchor settings, read from configuration on every call and validated as
 * they are read: which anchor keeps the seals
 * (`audit-log.integrity.anchor.driver`), the disk a disk anchor writes to
 * (`audit-log.integrity.anchor.disk`), the namespace on that disk it writes
 * under (`audit-log.integrity.anchor.path`), and how many seals one run anchors
 * (`audit-log.integrity.anchor.batch`).
 *
 * The driver fails closed: a missing one, `null`, an empty one or the string
 * `null` is no anchor, `disk` is the disk anchor, and anything else is refused
 * rather than read as either. The path is relative and can never leave its
 * namespace: no leading, trailing or doubled slash, and no `.` or `..` segment.
 * Every malformed value fails closed with an `InvalidArgumentException` naming
 * the key and never the value. Whether the disk is configured is a question for
 * `audit-log:check`, not for these settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AnchorSettings
{
    /** @var string What a path must be: segments of letters, digits, dots, underscores and hyphens, joined by single slashes. */
    public const string PATH_PATTERN = '/\A[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*\z/';

    /** @var string Prefix of every anchor setting's key. */
    private const string PREFIX = 'audit-log.integrity.anchor.';

    /** @var string What a disk name must be: 1 to 64 characters of valid UTF-8. */
    private const string DISK_PATTERN = '/\A.{1,64}\z/su';

    /** @var string The namespace a disk anchor writes under when none is configured. */
    private const string DEFAULT_PATH = 'audit-log-anchors';

    /** @var int Longest path, in characters. */
    private const int PATH_MAX_CHARACTERS = 191;

    /** @var array{0: int, 1: int, 2: int} Default, least and greatest number of seals one run anchors. */
    private const array BATCH = [100, 1, 10000];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * Which anchor keeps the seals: none when the driver is missing, `null`,
     * empty or the string `null`, and the disk anchor for `disk`.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver
     *
     * @throws \InvalidArgumentException
     */
    public function driver(): AnchorDriver
    {
        $driver = $this->config->get(self::PREFIX . 'driver');

        if ($driver === null || $driver === '') {
            return AnchorDriver::NONE;
        }

        return (is_string($driver) ? AnchorDriver::tryFrom($driver) : null)
            ?? throw new \InvalidArgumentException('`audit-log.integrity.anchor.driver` must be `null` or `disk`.');
    }

    /**
     * The disk a disk anchor writes to: the configured one, or the default disk
     * (`filesystems.default`) when none is configured or it is empty.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function disk(): string
    {
        $disk = $this->config->get(self::PREFIX . 'disk');

        if ($disk === null || $disk === '') {
            $disk = $this->config->get('filesystems.default');
        }

        if (!is_string($disk) || preg_match(self::DISK_PATTERN, $disk) !== 1) {
            throw new \InvalidArgumentException('`audit-log.integrity.anchor.disk` must be a disk name of 1 to 64 characters, or null or empty for the default disk.');
        }

        return $disk;
    }

    /**
     * The namespace on the disk a disk anchor writes under, `audit-log-anchors`
     * unless configured otherwise: 1 to 191 characters of path segments that
     * can never leave it.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function path(): string
    {
        $path = $this->config->get(self::PREFIX . 'path', self::DEFAULT_PATH);

        if (!is_string($path) || !self::isContainedPath($path)) {
            $message = '`audit-log.integrity.anchor.path` must be 1 to 191 characters of path segments of letters, digits,'
                . ' dots, underscores and hyphens, separated by single slashes, with no `.` or `..` segment.';

            throw new \InvalidArgumentException($message);
        }

        return $path;
    }

    /**
     * How many seals one run anchors, from 1 to 10000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function batch(): int
    {
        [$default, $least, $most] = self::BATCH;

        $key = self::PREFIX . 'batch';

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }

    /**
     * Read every anchor setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->driver();
        $this->disk();
        $this->path();
        $this->batch();
    }

    /**
     * Whether the path is within its length, is made of segments joined by
     * single slashes, and has no segment that names the current or the parent
     * directory: the one rule both these settings and a disk anchor hold a path
     * to.
     *
     * @param  string  $path
     * @return bool
     */
    public static function isContainedPath(string $path): bool
    {
        if (strlen($path) > self::PATH_MAX_CHARACTERS || preg_match(self::PATH_PATTERN, $path) !== 1) {
            return false;
        }

        return array_intersect(explode('/', $path), ['.', '..']) === [];
    }
}
