<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Config\ScheduleSetting;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;

/**
 * The sealing and verification settings under `audit-log.integrity`, read on
 * every call. A malformed value fails closed, naming only the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealSettings
{
    /** @var string Prefix of every sealing setting's key. */
    private const string PREFIX = 'audit-log.integrity.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting, by its key under the prefix. */
    private const array NUMBERS = [
        'seal.batch'                      => [5000, 100, 50000],
        'seal.max_batches'                => [100, 1, 100000],
        'seal.lookback_seconds'           => [3600, 0, 2592000],
        'seal.settle_seconds'             => [0, 0, 3600],
        'seal.max_attempts'               => [5, 1, 100],
        'verify.max_unsealed_age_seconds' => [90000, 600, 31536000],
    ];

    /** @var array<string, string> The default of each schedule, by its key under the prefix. */
    private const array SCHEDULES = [
        'seal.schedule'       => '*/5 * * * *',
        'seal.sweep_schedule' => '15 3 * * *',
        'verify.schedule'     => '45 3 * * *',
    ];

    /** @var string What a log id must be, after the key that holds it. */
    private const string LOG_ID_GRAMMAR = ' must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';

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
     * The id of the log every seal names: the configured one, or the source id
     * when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function logId(): string
    {
        $logId = $this->config->get(self::PREFIX . 'log_id');

        if ($logId === null || $logId === '') {
            return $this->sourceId();
        }

        if (!is_string($logId) || preg_match(SealEnvelope::LOG_ID_PATTERN, $logId) !== 1) {
            throw new \InvalidArgumentException('`audit-log.integrity.log_id`' . self::LOG_ID_GRAMMAR);
        }

        return $logId;
    }

    /**
     * The most entries one seal holds, from 100 to 50000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function batch(): int
    {
        return $this->number('seal.batch');
    }

    /**
     * The most seals one run writes, from 1 to 100000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxBatches(): int
    {
        return $this->number('seal.max_batches');
    }

    /**
     * How far before the newest seal's latest entry the recent pass starts, in
     * seconds, from 0 to 30 days.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function lookbackSeconds(): int
    {
        return $this->number('seal.lookback_seconds');
    }

    /**
     * How long an entry waits after it is recorded before a seal may hold it,
     * in seconds, from 0 to 3600.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function settleSeconds(): int
    {
        return $this->number('seal.settle_seconds');
    }

    /**
     * How many attempts one seal gets when it meets a concurrent writer, from 1
     * to 100.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAttempts(): int
    {
        return $this->number('seal.max_attempts');
    }

    /**
     * How old an unsealed entry may grow before verification calls it overdue,
     * in seconds, from 600 to a year.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxUnsealedAgeSeconds(): int
    {
        return $this->number('verify.max_unsealed_age_seconds');
    }

    /**
     * When sealing runs, as a cron expression, or `null` for never.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function sealSchedule(): ?string
    {
        return $this->schedule('seal.schedule');
    }

    /**
     * When the sweep runs, as a cron expression, or `null` for never.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function sweepSchedule(): ?string
    {
        return $this->schedule('seal.sweep_schedule');
    }

    /**
     * When a full, strict verification runs, as a cron expression, or `null`
     * for never.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function verifySchedule(): ?string
    {
        return $this->schedule('verify.schedule');
    }

    /**
     * Read every sealing setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->logId();

        foreach (array_keys(self::NUMBERS) as $setting) {
            $this->number($setting);
        }

        foreach (array_keys(self::SCHEDULES) as $setting) {
            $this->schedule($setting);
        }
    }

    /**
     * The source id, refused unless it fits the log id grammar.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function sourceId(): string
    {
        $sourceId = (new SourceSettings($this->config))->id();

        if (preg_match(SealEnvelope::LOG_ID_PATTERN, $sourceId) !== 1) {
            throw new \InvalidArgumentException('`audit-log.integrity.log_id` is empty, so `audit-log.source.id` is the log id, and it' . self::LOG_ID_GRAMMAR);
        }

        return $sourceId;
    }

    /**
     * The numeric setting under the key, within its range.
     *
     * @param  key-of<self::NUMBERS>  $setting
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $setting): int
    {
        [$default, $least, $most] = self::NUMBERS[$setting];

        $key = self::PREFIX . $setting;

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }

    /**
     * The schedule under the key: its default when it is not set, `null` when
     * it is `null` or empty, and otherwise a cron expression.
     *
     * @param  key-of<self::SCHEDULES>  $setting
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function schedule(string $setting): ?string
    {
        return ScheduleSetting::read($this->config, self::PREFIX . $setting, self::SCHEDULES[$setting]);
    }
}
