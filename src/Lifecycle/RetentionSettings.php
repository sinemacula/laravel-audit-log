<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Config\ScheduleSetting;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * The retention settings, read from configuration on every call and validated
 * as they are read: how many days entries are kept
 * (`audit-log.retention.after_days`, and per category
 * `audit-log.retention.categories`), how many days a category must stay
 * readable (`audit-log.retention.preserve`), how much one prune deletes at a
 * time and for how long it runs, and when the package schedules it.
 *
 * A number of days is 0 to 36500, and 0 is forever, both for a retention and
 * for a preservation. A missing number takes its default; a number is an
 * integer, or the canonical digit string an environment line gives, within its
 * range. Each map is keyed by categories of the event-definition grammar, and a
 * list, a key of no category or a malformed value is refused. A missing
 * schedule takes its default, `null` or an empty one schedules nothing, and
 * anything else must be a cron expression. A category kept for a finite time
 * shorter than it must be preserved is refused before any run. Every malformed
 * value fails closed with an `InvalidArgumentException` naming the key and
 * never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RetentionSettings
{
    /** @var int Most days a retention or a preservation may be, a hundred years: some regulators ask for more than ten. */
    public const int MAX_DAYS = 36500;

    /** @var int The shortest time budget of one prune, in seconds: a minute. */
    public const int LEAST_SECONDS = 60;

    /** @var int The longest time budget of one prune, in seconds: a day. */
    public const int MOST_SECONDS = 86400;

    /** @var string Prefix of every retention setting's key. */
    private const string PREFIX = 'audit-log.retention.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting, by its key under the prefix. */
    private const array NUMBERS = [
        'after_days'  => [0, 0, self::MAX_DAYS],
        'batch'       => [1000, 100, 10000],
        'max_seconds' => [3000, self::LEAST_SECONDS, self::MOST_SECONDS],
    ];

    /** @var string The default schedule of the prune. */
    private const string SCHEDULE = '30 3 * * *';

    /** @var string What a map of days must be, after the key that holds it. */
    private const string MAP_GRAMMAR = ' must be a map of categories to days, each from 0 to 36500, 0 meaning forever.';

    /** @var string What each key of a map of days must be, after the key that holds it. */
    private const string CATEGORY_GRAMMAR = ' must be keyed by categories of 1 to 64 lower-case letters, digits or underscores, starting with a letter.';

    /** @var string The refusal of a retention shorter than its preservation, by the retention's key and the preservation's. */
    private const string CONFLICT = '`%s` is shorter than `%s`; a category must be kept at least as long as it is preserved.';

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
     * How many days an entry of a category with no retention of its own is
     * kept, from 0 to 36500, 0 meaning forever.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function afterDays(): int
    {
        return $this->number('after_days');
    }

    /**
     * How many days the entries of each category named are kept, from 0 to
     * 36500, 0 meaning forever, by category in bytewise order.
     *
     * @return array<string, int>
     *
     * @throws \InvalidArgumentException
     */
    public function categories(): array
    {
        return $this->days('categories');
    }

    /**
     * How many days the entries of each category named must stay readable, from
     * 0 to 36500, 0 meaning forever, by category in bytewise order.
     *
     * @return array<string, int>
     *
     * @throws \InvalidArgumentException
     */
    public function preserve(): array
    {
        return $this->days('preserve');
    }

    /**
     * The most entries one chunk of a prune deletes, from 100 to 10000.
     *
     * @return positive-int
     *
     * @throws \InvalidArgumentException
     */
    public function batch(): int
    {
        return $this->number('batch');
    }

    /**
     * How long one prune runs before it stops between chunks, in seconds, from
     * a minute to a day.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxSeconds(): int
    {
        return $this->number('max_seconds');
    }

    /**
     * When the prune runs, as a cron expression, or `null` for never.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function schedule(): ?string
    {
        return ScheduleSetting::read($this->config, self::PREFIX . 'schedule', self::SCHEDULE);
    }

    /**
     * Whether any entry is kept for less than forever: the default retention,
     * or the retention of any category, is a number of days.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function retainsAnythingForLess(): bool
    {
        if ($this->afterDays() > 0) {
            return true;
        }

        return array_filter($this->categories(), static fn (int $days): bool => $days > 0) !== [];
    }

    /**
     * Read every retention setting, failing on the first malformed one, then
     * refuse a category kept for a finite time shorter than it is preserved.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        foreach (array_keys(self::NUMBERS) as $setting) {
            $this->number($setting);
        }

        $this->schedule();

        $afterDays  = $this->afterDays();
        $categories = $this->categories();

        foreach ($this->preserve() as $category => $preserved) {
            $kept = $categories[$category] ?? $afterDays;

            if ($kept === 0 || ($preserved !== 0 && $kept >= $preserved)) {
                continue;
            }

            $retention = array_key_exists($category, $categories) ? 'categories.' . $category : 'after_days';

            throw new \InvalidArgumentException(sprintf(self::CONFLICT, self::PREFIX . $retention, self::PREFIX . 'preserve.' . $category));
        }
    }

    /**
     * The numeric setting under the key, within its range.
     *
     * @param  key-of<self::NUMBERS>  $setting
     * @return ($setting is 'after_days' ? int : positive-int)
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
     * The map of days under the key: empty when it is not set or is `null`, and
     * otherwise a map of categories to days from 0 to 36500, sorted bytewise by
     * category.
     *
     * @param  'categories'|'preserve'  $setting
     * @return array<string, int>
     *
     * @throws \InvalidArgumentException
     */
    private function days(string $setting): array
    {
        $key = self::PREFIX . $setting;
        $map = $this->config->get($key) ?? [];

        if (!is_array($map) || ($map !== [] && array_is_list($map))) {
            throw new \InvalidArgumentException('`' . $key . '`' . self::MAP_GRAMMAR);
        }

        $days = [];

        foreach ($map as $category => $value) {
            if (!is_string($category) || preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
                throw new \InvalidArgumentException('`' . $key . '`' . self::CATEGORY_GRAMMAR);
            }

            $days[$category] = IntegerSetting::from('`' . $key . '.' . $category . '`', $value, 0, self::MAX_DAYS);
        }

        ksort($days, SORT_STRING);

        return $days;
    }
}
