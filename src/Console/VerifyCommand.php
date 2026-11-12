<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `audit-log:verify`: verifies the whole log, or the seals from `--from` to
 * `--to`, with the lifecycle journal and, for the whole log, the key store.
 *
 * Nothing printed, dispatched or reported holds a failure's message, a
 * statement, a binding or an entry value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:verify')]
final class VerifyCommand extends Command
{
    /** @var string The command the event and the exception name. */
    private const string COMMAND = 'verify';

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:verify'
        . ' {--from= : The first seal to verify, by sequence}'
        . ' {--to= : The last seal to verify, by sequence}'
        . ' {--json : Write one JSON object per line}'
        . ' {--strict : Also fail on any seal the configured anchor does not confirm}'
        . ' {--sweep-first : Seal the whole table from the sweep\'s cursor before verifying}';

    /** @var string The console command description. */
    protected $description = 'Verify the audit log\'s seals, the entries they hold and their anchoring';

    /**
     * Verify the range the options give, after a sweep when asked, and alarm on
     * a failure.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return int
     */
    public function handle(Container $container, IntegrityAlarm $alarm): int
    {
        try {
            $range = new VerificationRange($this->sequence('from'), $this->sequence('to'));
        } catch (\InvalidArgumentException $refusal) {
            // The refusal names the option and its range, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        $swept  = $this->hasSweptWhenAsked();
        $strict = $this->option('strict') === true;
        $tally  = new VerificationTally;

        try {
            $summary = $container->make(Verifier::class)->verify($range, function (SegmentReport $report) use ($tally): void {
                $this->stream($report, $tally);
            }, $strict);
        } catch (\Throwable $exception) {
            return $this->stopped($exception, $tally, $alarm);
        }

        $exit = $this->conclude($summary, $strict, $alarm);

        return $swept ? $exit : self::FAILURE;
    }

    /**
     * Print the run's findings and summary, alarm when it fails, and return the
     * exit code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @param  bool  $strict
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function conclude(VerificationSummary $summary, bool $strict, IntegrityAlarm $alarm): int
    {
        if ($this->isJson()) {
            $this->printJson($summary, $strict);
        } else {
            $this->printText($summary, $strict);
        }

        if (!$summary->fails($strict)) {
            return self::SUCCESS;
        }

        $alarm->raise($summary->toEvent(self::COMMAND));

        return self::FAILURE;
    }

    /**
     * Count the report and print its line, as its seal is verified.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $report
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function stream(SegmentReport $report, VerificationTally $tally): void
    {
        $tally->add($report);

        if ($this->isJson()) {
            $this->json($report->toArray());

            return;
        }

        $this->line(VerifyLines::segmentLine($report));
    }

    /**
     * Write each finding of the run, then the summary, as one JSON object each.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @param  bool  $strict
     * @return void
     *
     * @throws \JsonException
     */
    private function printJson(VerificationSummary $summary, bool $strict): void
    {
        foreach ($summary->findings as $finding) {
            $this->json($finding->toArray());
        }

        $this->json($summary->toArray($strict));
    }

    /**
     * Print each finding of the run, then the summary and the verdict as text.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @param  bool  $strict
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function printText(VerificationSummary $summary, bool $strict): void
    {
        foreach ($summary->findings as $finding) {
            $this->line(VerifyLines::findingLine($finding));
        }

        $this->line(VerifyLines::coverage($summary) . ' ' . VerifyLines::anchorClause($summary));
        $this->line(VerifyLines::integrityLine($summary->integrity));
        $this->line(VerifyLines::anchoringLine($summary->anchoring, $summary->awaiting));

        if ($summary->journal !== null) {
            $this->line(VerifyLines::journalLine($summary->journal));
        }

        if ($summary->keys !== null) {
            $this->line(VerifyLines::keysLine($summary->keys));
        }

        $this->line($summary->complete
            ? sprintf('Unsealed: %d pending, %d overdue.', $summary->pending, $summary->overdue)
            : 'This run checked a range; it does not establish the integrity of the whole log.');

        if ($summary->fails($strict)) {
            $this->error('Verification failed.');

            return;
        }

        $this->info('Verification passed.');
    }

    /**
     * Print and alarm for a run that stopped, naming the failure by its class;
     * a refused range prints why and alarms nothing.
     *
     * @param  \Throwable  $exception
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityAlarm  $alarm
     * @return int
     */
    private function stopped(#[\SensitiveParameter] \Throwable $exception, VerificationTally $tally, IntegrityAlarm $alarm): int
    {
        if (self::isRangeRefusal($exception)) {
            // A range refusal names an option and the head, never a value
            $this->error($exception->getMessage());

            return self::INVALID;
        }

        $class = get_debug_type($exception);

        $this->error(sprintf('Verification stopped with %s.', $class));

        $event = new IntegrityCheckFailed(self::COMMAND, $tally->integrity(), $tally->anchoring(), null, null, null, null, false);

        $alarm->raise($event, IntegrityCheckFailedException::stopped(self::COMMAND, $class));

        return self::FAILURE;
    }

    /**
     * Run the sweep first when asked, silently with `--json`, and return
     * whether it succeeded; a failed sweep has already alarmed.
     *
     * @return bool
     */
    private function hasSweptWhenAsked(): bool
    {
        if ($this->option('sweep-first') !== true) {
            return true;
        }

        $arguments = ['--sweep' => true];

        return ($this->isJson() ? $this->callSilently('audit-log:seal', $arguments) : $this->call('audit-log:seal', $arguments)) === self::SUCCESS;
    }

    /**
     * Write the line as one JSON object.
     *
     * @param  array<string, array<string, bool|int|string|null>|bool|int|string|null>  $line
     * @return void
     *
     * @throws \JsonException
     */
    private function json(array $line): void
    {
        // Written raw, so nothing an id holds is read as a style
        $this->output->writeln(json_encode($line, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE), OutputInterface::OUTPUT_RAW);
    }

    /**
     * The sequence the option gives, or `null` when it is not given.
     *
     * @param  'from'|'to'  $option
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    private function sequence(string $option): ?int
    {
        $value = $this->option($option);

        return $value === null ? null : IntegerSetting::from(sprintf('The --%s option', $option), $value, 1, PHP_INT_MAX);
    }

    /**
     * Whether each line is written as one JSON object.
     *
     * @return bool
     */
    private function isJson(): bool
    {
        return $this->option('json') === true;
    }

    /**
     * Whether the failure is the range's own refusal, told apart by where it
     * was raised, never by its text.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isRangeRefusal(#[\SensitiveParameter] \Throwable $exception): bool
    {
        return $exception instanceof \InvalidArgumentException && ($exception->getTrace()[0]['class'] ?? null) === VerificationRange::class;
    }
}
