<?php

declare(strict_types = 1);

namespace Tests\Feature\Stores;

use Illuminate\Log\LogManager;
use Monolog\Handler\NullHandler;
use Monolog\Logger as Monolog;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\AuditLog\Stores\DirectLog;
use Tests\TestCase;

/**
 * Feature tests for reaching a channel's own logger past Laravel's wrapper, and
 * leaving alone a channel that is no wrapper.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DirectLog::class)]
final class DirectLogTest extends TestCase
{
    /**
     * Laravel's wrapper gives way to the logger it holds, named by the channel.
     *
     * @return void
     */
    public function testReachesTheLoggerInsideLaravelsWrapper(): void
    {
        config()->set('logging.channels.direct', ['driver' => 'monolog', 'handler' => NullHandler::class]);

        $logger = DirectLog::channel(app(LogManager::class), 'direct');

        self::assertInstanceOf(Monolog::class, $logger);
        self::assertSame('testing', $logger->getName());
    }

    /**
     * A channel that is no wrapper is the logger.
     *
     * @return void
     */
    public function testLeavesAnyOtherLoggerAlone(): void
    {
        $logger  = \Mockery::mock(LoggerInterface::class);
        $manager = \Mockery::mock(LogManager::class);

        $manager->allows('channel')->with('plain')->andReturn($logger);

        self::assertSame($logger, DirectLog::channel($manager, 'plain'));
    }
}
