<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\JournalSummary;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `audit-log:verify`: verifies the whole log, or the seals from `--from` to
 * `--to` by sequence, and prints a line for each seal as it is verified, then a
 * line for each finding of the run as a whole, then the summary: the exact
 * range checked, the head observed and the anchor's, the seals in each
 * integrity and anchoring status, those awaiting their first anchoring, the
 * lifecycle journal's section, and, for the whole log, the unsealed entries.
 * `--json` writes each line as one JSON object, the summary last.
 * `--sweep-first` runs `audit-log:seal --sweep` before verifying, so an entry
 * inserted late since the last sweep, such as a replayed record, is sealed
 * rather than found overdue; the scheduled verification sweeps first. With
 * `--json` the sweep prints nothing, and a sweep that fails has already alarmed
 * and makes the run exit non-zero.
 *
 * Every run, a ranged one included, verifies the whole lifecycle journal: its
 * chain, each row's signature and the transitions it makes, and each seal's
 * commitment to it. Its section says how many rows it read, the sequence of the
 * chain's head and the sequence the latest seal commits to, and what it finds
 * (`journal_gap`, `journal_signature`, `journal_commitment`,
 * `journal_transition`, `journal_key` and `journal_malformed`) is a finding of
 * the run, printed and failing it as any other.
 *
 * A ranged run says it does not establish the integrity of the whole log. An
 * option that is not a sequence, a first seal after the last, an end beyond the
 * head and a range of a log with no seal are refused before anything is
 * verified, and exit with `INVALID`, alarming nothing.
 *
 * A run fails on any seal or finding that is tampered, incomplete or
 * unverifiable, and, with `--strict` and an anchor configured, on anything the
 * anchor does not confirm, a seal still awaiting its first anchoring excepted.
 * A failure prints its verdict, dispatches a payload-free
 * `IntegrityCheckFailed` whose maps list every status, and reports an
 * `IntegrityCheckFailedException`; a run that stops is named by the class of
 * what stopped it, and alarms the same way, with no finding. The verifier is
 * resolved inside the run, so an anchor that cannot be built from its settings
 * stops the run and alarms. Each exits non-zero. A listener that fails is
 * reported and hides nothing, and a reporter that fails hides nothing. Nothing
 * the package prints, dispatches or reports holds a message of a failure, a
 * statement, a binding or a value of an entry.
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

    /** @var string How an id the line has none of is written. */
    private const string NONE = 'none';

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
     * Verify the range the options give, after a sweep when asked, printing
     * each seal as it is verified, then the findings and the summary, and alarm
     * on a failure.
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
     * Print the findings of the run and its summary, and alarm when it fails.
     * The exit code the run earns is returned.
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

        $this->line(self::segmentLine($report));
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
     * Print each finding of the run, then the summary as text: the coverage,
     * the counts, the journal, the unsealed entries of a run of the whole log
     * or the caveat of a ranged run, and the verdict.
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
            $this->line(self::findingLine($finding));
        }

        $this->line(self::coverage($summary) . ' ' . self::anchorClause($summary));
        $this->line(self::integrityLine($summary->integrity));
        $this->line(self::anchoringLine($summary->anchoring, $summary->awaiting));

        if ($summary->journal !== null) {
            $this->line(self::journalLine($summary->journal));
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
     * Print that the run stopped with a failure, named by its class alone,
     * alarm with the seals verified before it stopped and no finding, and
     * return the exit code a stopped run earns. A refused range instead prints
     * why and alarms nothing.
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
     * Sweep the table before verifying when asked, printing what the sweep did
     * unless each line is JSON. Whether the sweep, if any, succeeded is
     * returned; one that failed has already alarmed.
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
     * @param  array<string, array<string, int|null>|bool|int|string|null>  $line
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
     * The line of a verified seal: its sequence and id, its integrity and
     * anchoring, the member rows found, whether it awaits its first anchoring,
     * and the finding and the id it was found at, if any.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $report
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function segmentLine(SegmentReport $report): string
    {
        $line = sprintf(
            'seal %d %s integrity=%s anchoring=%s members=%d',
            $report->sequence,
            self::id($report->sealId),
            $report->integrity->value,
            $report->anchoring->value,
            $report->members,
        );

        if ($report->awaitingAnchor) {
            $line .= ' awaiting-anchor';
        }

        if ($report->finding === null) {
            return $line;
        }

        return $line . sprintf(' finding=%s first=%s', $report->finding->value, self::id($report->firstBadId));
    }

    /**
     * The line of a finding of the run as a whole: the check, the status it
     * gives, how many times it was found and the first id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RunFinding  $finding
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function findingLine(RunFinding $finding): string
    {
        return sprintf('finding %s integrity=%s count=%d first=%s', $finding->finding->value, $finding->status()->value, $finding->count, self::id($finding->firstBadId));
    }

    /**
     * The id as a line of text shows it: repaired and stripped of control
     * characters, with nothing in it read as a style, or `none` when there is
     * no id to name, since an id read from a table that was altered may hold
     * anything.
     *
     * @param  ?string  $id
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function id(?string $id): string
    {
        return $id === null || $id === '' ? self::NONE : OutputFormatter::escape(TextSanitizer::clean($id));
    }

    /**
     * The line of the seals in each integrity status.
     *
     * @param  array<string, int>  $integrity
     * @return string
     */
    private static function integrityLine(array $integrity): string
    {
        return sprintf(
            'Integrity: %d valid, %d pruned, %d incomplete, %d unverifiable, %d tampered.',
            $integrity[IntegrityStatus::VALID->value],
            $integrity[IntegrityStatus::PRUNED->value],
            $integrity[IntegrityStatus::INCOMPLETE->value],
            $integrity[IntegrityStatus::UNVERIFIABLE->value],
            $integrity[IntegrityStatus::TAMPERED->value],
        );
    }

    /**
     * The line of the seals in each anchoring status, with those unanchored
     * only while they await their first anchoring.
     *
     * @param  array<string, int>  $anchoring
     * @param  int  $awaiting
     * @return string
     */
    private static function anchoringLine(array $anchoring, int $awaiting): string
    {
        return sprintf(
            'Anchoring: %d anchored, %d unanchored (%d awaiting their first anchoring), %d unavailable, %d contradicted.',
            $anchoring[AnchorStatus::ANCHORED->value],
            $anchoring[AnchorStatus::UNANCHORED->value],
            $awaiting,
            $anchoring[AnchorStatus::UNAVAILABLE->value],
            $anchoring[AnchorStatus::CONTRADICTED->value],
        );
    }

    /**
     * The line of the lifecycle journal: the rows read, the sequence of the
     * chain's head, and the sequence the latest seal commits to.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSummary  $journal
     * @return string
     */
    private static function journalLine(JournalSummary $journal): string
    {
        return sprintf(
            'Journal: %d rows to sequence %s; the latest seal commits to %s.',
            $journal->rowsRead,
            $journal->head      ?? self::NONE,
            $journal->committed ?? self::NONE,
        );
    }

    /**
     * The seals the run checked and the head it observed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @return string
     */
    private static function coverage(VerificationSummary $summary): string
    {
        if ($summary->head === null) {
            return 'Checked no seals: the log has none;';
        }

        return sprintf('Checked seals %d to %d of head %d;', $summary->from, $summary->to, $summary->head);
    }

    /**
     * What the run learnt of the anchor's head.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @return string
     */
    private static function anchorClause(VerificationSummary $summary): string
    {
        return match (true) {
            !$summary->anchorConfigured                     => 'no anchor is configured.',
            !$summary->discovers                            => 'the anchor cannot report its head.',
            $summary->remote === AnchorStatus::UNAVAILABLE  => 'the anchor is unavailable.',
            $summary->remoteHead !== null                   => sprintf('the anchor\'s head is %d.', $summary->remoteHead),
            $summary->remote === AnchorStatus::CONTRADICTED => 'the anchor holds another digest for a seal.',
            default                                         => 'the anchor holds no seal.',
        };
    }

    /**
     * Whether the failure is the range's own refusal: an end that is not a
     * sequence, a first seal after the last, an end beyond the head the run
     * observed, or a range of a log with no seal. Only the range raises one, so
     * it is told apart by where it was raised, and never by its text.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isRangeRefusal(#[\SensitiveParameter] \Throwable $exception): bool
    {
        return $exception instanceof \InvalidArgumentException && ($exception->getTrace()[0]['class'] ?? null) === VerificationRange::class;
    }
}
