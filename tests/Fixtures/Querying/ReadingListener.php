<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Querying;

use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * An `AuditRecorded` listener that reads the trail's first page for each record
 * it hears, as a feed would, keeping each code heard and each page or refusal
 * in the order the reads ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReadingListener
{
    /** @var list<string> The code of every record it heard, in order. */
    private array $heard = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException|\SineMacula\Laravel\AuditLog\Querying\TrailPage> What each read gave it, in the order the reads ended. */
    private array $caught = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  string  $category
     */
    public function __construct(

        /** The viewer it reads the trail for. */
        private readonly Reference $viewer,

        /** The category it reads. */
        private readonly string $category = 'finance',
    ) {}

    /**
     * Read the first page of the trail, keeping the page, or the refusal of the
     * read when it is refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\AuditRecorded  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    public function __invoke(AuditRecorded $event): void
    {
        $this->heard[] = $event->code;

        try {
            $this->caught[] = app(AuditTrail::class)->visibleTo($this->viewer)->inCategory($this->category)->cursorPaginate();
        } catch (AuditReadRefusedException $refusal) {
            $this->caught[] = $refusal;
        }
    }

    /**
     * The code of every record it heard, in order.
     *
     * @return list<string>
     */
    public function heard(): array
    {
        return $this->heard;
    }

    /**
     * What each read gave it, the page or the refusal, in the order the reads
     * ended.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException|\SineMacula\Laravel\AuditLog\Querying\TrailPage>
     */
    public function caught(): array
    {
        return $this->caught;
    }

    /**
     * The refusals it caught, in the order the reads ended.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException>
     */
    public function refusals(): array
    {
        return array_values(array_filter($this->caught, static fn (AuditReadRefusedException|TrailPage $caught): bool => $caught instanceof AuditReadRefusedException));
    }

    /**
     * The pages it read, in the order the reads ended.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>
     */
    public function pages(): array
    {
        return array_values(array_filter($this->caught, static fn (AuditReadRefusedException|TrailPage $caught): bool => $caught instanceof TrailPage));
    }
}
