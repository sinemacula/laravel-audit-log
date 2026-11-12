<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:erase`: erases an owner by destroying the owner's keys, or with
 * `--reapply=<file>` erases every owner an erasures file names again.
 *
 * A failure prints its class alone, since its message can carry a statement's
 * bindings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:erase')]
final class EraseCommand extends Command
{
    /** @var string Why `--reapply` given with an owner, `--partial` or `--pending` is refused. */
    private const string REAPPLY_ALONE = 'The --reapply option takes no owner, --partial or --pending; it erases each owner in part, accepting pending deliveries.';

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:erase'
        . ' {type? : The type of the owner to erase}'
        . ' {id? : The id of the owner to erase}'
        . ' {--by-type= : The type of the operator erasing the owner}'
        . ' {--by-id= : The id of the operator erasing the owner}'
        . ' {--reason= : The reason code the owner is erased for}'
        . ' {--reference= : The ticket or case the erasure answers to}'
        . ' {--partial : Destroy the keys nothing blocks and keep the rest}'
        . ' {--pending : Erase over outbox rows older than the erasure}'
        . ' {--reapply= : Erase again every owner the erasures file names, after a restore}';

    /** @var string The console command description. */
    protected $description = 'Erase an owner\'s encrypted audit fields by destroying the owner\'s keys';

    /**
     * Erase the owner the arguments name, or every owner the reapply file
     * names, and print what was done.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $authority = LifecycleOptions::authority($this);
            $reapply   = $this->reapplyFile();
            $owner     = $reapply === null ? LifecycleOptions::owner($this) : null;
        } catch (\InvalidArgumentException $refusal) {
            // Each refusal names the argument or option, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        if ($owner !== null) {
            return $this->erase($lifecycle, $owner, $authority);
        }

        return $this->reapply($lifecycle, $reapply, $authority);
    }

    /**
     * Erase the owner, print what the erasure did or why it was refused, and
     * return the exit code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return int
     */
    private function erase(AuditLifecycle $lifecycle, #[\SensitiveParameter] Reference $owner, Authority $authority): int
    {
        try {
            $result = $lifecycle->erase($owner, $authority, $this->option('partial') === true, $this->option('pending') === true);
        } catch (ErasureRefusedException $refusal) {
            $this->error(sprintf('The erasure was refused (%s); nothing was written.', $refusal->refusal()->value));
            $this->line(sprintf('Owner fingerprint %s (key %s).', $refusal->fingerprint(), $refusal->fingerprintKey()));
            $this->printReasons('Refused for', $refusal->reasons());

            return self::FAILURE;
        } catch (\Throwable $exception) {
            $this->error(sprintf('The erasure failed with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->printErasure($result);

        return self::SUCCESS;
    }

    /**
     * Erase again every owner the file names, print what was done and whether
     * the restore is reconciled, and return the exit code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return int
     */
    private function reapply(AuditLifecycle $lifecycle, string $path, Authority $authority): int
    {
        try {
            $result = $lifecycle->reapplyErasures($path, $authority);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The reapply failed with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->printReapply($result);

        return $result->reconciled ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The erasures file `--reapply` names, or `null` without the option;
     * refused unless it is readable and given alone.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function reapplyFile(): ?string
    {
        $path = $this->option('reapply');

        if ($path === null) {
            return null;
        }

        $alone = $this->argument('type') === null && $this->argument('id') === null && $this->option('partial') !== true && $this->option('pending') !== true;

        if (!$alone) {
            throw new \InvalidArgumentException(self::REAPPLY_ALONE);
        }

        if (!is_string($path) || $path === '' || !is_file($path) || !is_readable($path)) {
            throw new \InvalidArgumentException('The --reapply option must name a readable erasures file.');
        }

        return $path;
    }

    /**
     * Print how the erasure ended, its row, fingerprint and counts, the reasons
     * a key was kept, and a warning when its record was not written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $result
     * @return void
     */
    private function printErasure(ErasureResult $result): void
    {
        $this->line(sprintf('Erasure %s: %s.', $result->operationId, $result->status->value));

        if ($result->erasureId !== null) {
            $this->line(sprintf('Journal row %s.', $result->erasureId));
        }

        $this->line(sprintf('Owner fingerprint %s (key %s).', $result->fingerprint, $result->fingerprintKey));
        $this->line(sprintf('Destroyed %d keys and kept %d; %d entries affected.', $result->keysDestroyed, $result->keysKept, $result->entriesAffected));
        $this->printReasons('Kept for', $result->blocked);

        if ($result->pendingAccepted) {
            $this->line('Accepted outbox rows older than the erasure; their fields are erased with the keys.');
        }

        if ($result->recorded) {
            return;
        }

        $this->warn('The erasure\'s audit_log.subject_erased record could not be written; audit-log:reconcile writes it from the journal.');
    }

    /**
     * Print what the reapply did, and whether the restore is reconciled.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult  $result
     * @return void
     */
    private function printReapply(ReapplyResult $result): void
    {
        $this->line(sprintf('Reapply %s of file %s.', $result->operationId, $result->fileSha256));
        $this->line(sprintf(
            'Owners %d: %d erased, %d already erased, %d erased in part, %d refused; %d lines rejected.',
            $result->owners,
            $result->erased,
            $result->alreadyErased,
            $result->partial,
            $result->refused,
            $result->rejected,
        ));

        if (!$result->recorded) {
            $this->warn('An erasure\'s audit_log.subject_erased record could not be written; audit-log:reconcile writes it from the journal.');
        }

        if (!$result->reconciled) {
            $this->error('The restore is not reconciled: every owner must end erased or already erased, and every line name an owner.');

            return;
        }

        $this->line(sprintf('Restore reconciled in journal row %s, at anchored sequence %s.', $result->reconciliationId, $result->anchoredSequence ?? 'none'));
    }

    /**
     * Print the reasons, each once, after the label, when there are any.
     *
     * @param  string  $label
     * @param  list<string>  $reasons
     * @return void
     */
    private function printReasons(string $label, array $reasons): void
    {
        if ($reasons === []) {
            return;
        }

        $this->line(sprintf('%s: %s.', $label, implode(', ', $reasons)));
    }
}
