<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\ReinstatementRefusedException;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:reinstate`: reinstates an erased owner, so a key may be created
 * for the owner again in a generation above the floor of its erasure,
 * journalled behind the lifecycle lock and decided from the owner's latest
 * marker and the verified journal, then records it. A reinstatement creates no
 * key and makes no erased field readable again.
 *
 * The owner is named by the `type` and `id` arguments. It trusts the shell, as
 * every maintenance command does: `--by-type` and `--by-id` assert the operator
 * and prove nothing of who runs it, and the boundary is the maintenance
 * connection's credentials. It prints the operation's id, the reinstatement's
 * journal row, the owner's keyed fingerprint and the id of the ring key it was
 * taken under, never the owner, the generation floor, and a warning when the
 * record could not be written. An owner who is not erased is refused, recorded
 * `denied`, and exits 1, as does any other failure, printed by its class alone
 * and never its message; an argument or option it refuses exits 2 before
 * anything runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:reinstate')]
final class ReinstateCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:reinstate'
        . ' {type : The type of the owner to reinstate}'
        . ' {id : The id of the owner to reinstate}'
        . ' {--by-type= : The type of the operator reinstating the owner}'
        . ' {--by-id= : The id of the operator reinstating the owner}'
        . ' {--reason= : The reason code the owner is reinstated for}'
        . ' {--reference= : The ticket or case the reinstatement answers to}';

    /** @var string The console command description. */
    protected $description = 'Reinstate an erased owner, so new keys may be created for it';

    /**
     * Reinstate the owner the arguments name, once the arguments and options
     * are known to be well formed, and print it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $authority = LifecycleOptions::authority($this);
            $owner     = LifecycleOptions::owner($this);
        } catch (\InvalidArgumentException $refusal) {
            // Each refusal names the argument or option, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        try {
            $result = $lifecycle->reinstate($owner, $authority);
        } catch (\Throwable $exception) {
            $this->error($exception instanceof ReinstatementRefusedException
                ? 'The owner is not erased; nothing was reinstated.'
                : sprintf('The reinstatement failed with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->line(sprintf('Reinstatement %s: journal row %s.', $result->operationId, $result->reinstatementId));
        $this->line(sprintf('Owner fingerprint %s (key %s).', $result->fingerprint, $result->fingerprintKey));
        $this->line(sprintf('The owner\'s next key of any unit is created above generation %d.', $result->generationFloor));

        if (!$result->recorded) {
            $this->warn('The reinstatement\'s audit_log.keys_reinstated record could not be written; audit-log:reconcile writes it from the journal.');
        }

        return self::SUCCESS;
    }
}
