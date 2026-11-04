<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:release`: releases an active hold, journalled behind the lifecycle
 * lock and decided from the verified journal, never from the holds projection,
 * then records it.
 *
 * It trusts the shell, as every maintenance command does: `--by-type` and
 * `--by-id` assert the operator and prove nothing of who runs it, and the
 * boundary is the maintenance connection's credentials. It prints the hold
 * released, and a warning when its record could not be written, since
 * `audit-log:reconcile` writes it from the journal. A hold the journal does not
 * hold active, never placed or released already, is refused, recorded
 * `denied`, and exits 1, as does any other refusal, named by its class alone;
 * a hold id that is not a lower-case UUID v7, or an option it refuses, exits 2
 * before anything runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:release')]
final class ReleaseCommand extends Command
{
    /** @var string Pattern of a hold id the package mints: a lower-case UUID v7. */
    private const string HOLD_ID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:release'
        . ' {hold : The id of the hold to release}'
        . ' {--by-type= : The type of the operator releasing the hold}'
        . ' {--by-id= : The id of the operator releasing the hold}'
        . ' {--reason= : The reason code the hold is released for}'
        . ' {--reference= : The ticket or case the release answers to}';

    /** @var string The console command description. */
    protected $description = 'Release a hold on audit entries';

    /**
     * Release the hold the argument names, once the options are known to be
     * well formed, and print it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $holdId    = $this->holdId();
            $authority = LifecycleOptions::authority($this);
        } catch (\InvalidArgumentException $refusal) {
            // Each refusal names the option, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        try {
            $result = $lifecycle->release($holdId, $authority);
        } catch (\Throwable $exception) {
            $this->error($exception instanceof UnknownHoldException
                ? sprintf('The hold %s is not active; only an active hold is released.', $holdId)
                : sprintf('The release was refused with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->line(sprintf('Released hold %s.', $result->hold->id));

        if (!$result->recorded) {
            $this->warn('The release\'s audit_log.released record could not be written; audit-log:reconcile writes it from the journal.');
        }

        return self::SUCCESS;
    }

    /**
     * The hold id the argument gives: a lower-case UUID v7, the form of every
     * hold id the package mints.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function holdId(): string
    {
        $holdId = $this->argument('hold');

        if (is_string($holdId) && preg_match(self::HOLD_ID_PATTERN, $holdId) === 1) {
            return $holdId;
        }

        throw new \InvalidArgumentException('The hold must be named by its id, a lower-case UUID v7.');
    }
}
