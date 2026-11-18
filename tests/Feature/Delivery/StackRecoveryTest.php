<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for a sync-mode stack whose second destination fails, from the
 * record to the replay of its spill.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
#[CoversClass(FailureHandler::class)]
#[CoversClass(StackAuditStore::class)]
#[CoversClass(Replayer::class)]
final class StackRecoveryTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore;

    /** @var ?string The spill file the test wrote. */
    private ?string $path = null;

    /**
     * Remove the spill file the test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->path !== null && is_file($this->path)) {
            unlink($this->path);
        }

        parent::tearDown();
    }

    /**
     * The failed destination spills the whole record while the database keeps
     * it; each replay stores nothing twice and calls the failed destination
     * again.
     *
     * @return void
     */
    public function testAFailedDestinationSpillsTheRecordAndEachReplayCallsItAgain(): void
    {
        $reporter = new RecordingExceptionHandler;
        $down     = true;
        $calls    = 0;
        $failed   = [];
        $recorded = 0;

        app()->instance(ExceptionHandler::class, $reporter);
        app()->instance(AuditStore::class, new StackAuditStore([
            'database' => $this->store(),
            'siem'     => new CallbackStore(static function () use (&$down, &$calls): void {
                if ($down) {
                    throw new \RuntimeException('The siem is down.');
                }

                $calls++;
            }),
        ]));

        Event::listen(AuditWriteFailed::class, static function (AuditWriteFailed $event) use (&$failed): void {
            $failed[] = $event->id;
        });

        Event::listen(AuditRecorded::class, static function () use (&$recorded): void {
            $recorded++;
        });

        $this->captureLogLines();

        $record  = AuditLog::event('invoice.approved')->record();
        $reports = $reporter->reports();

        self::assertSame(1, $this->entryCount());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertSame('siem', $reports[0]->destination);
        self::assertSame([$record->id], $failed);
        self::assertSame(0, $recorded);

        $down       = false;
        $this->path = (string) tempnam(sys_get_temp_dir(), 'audit-log-spill');

        file_put_contents($this->path, $this->spillLines()[0] . "\n");

        self::assertSame(1, app(Replayer::class)->spill($this->path, false)->replayed());
        self::assertSame([1, 1, 1], [$this->entryCount(), $calls, $recorded]);

        app(Replayer::class)->spill($this->path, false);

        self::assertSame([1, 2], [$this->entryCount(), $calls]);
    }
}
