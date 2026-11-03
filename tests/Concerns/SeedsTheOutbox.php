<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Encryption\StringEncrypter;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Puts records in the outbox as the outbox write path does: each finalised
 * once, encoded as its envelope, encrypted as a string with the application's
 * encrypter and seeded under its own id, so a drain reads back exactly what
 * that path would have written.
 *
 * A class using it also uses `InteractsWithOutbox`, whose `seedOutboxRow()`
 * writes the row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SeedsTheOutbox
{
    /**
     * Seed an outbox row under the id holding the payload, as
     * `InteractsWithOutbox` does.
     *
     * @param  string  $id
     * @param  string  $payload
     * @param  array<string, int|string|null>  $columns
     * @return void
     */
    abstract protected function seedOutboxRow(string $id, string $payload, array $columns = []): void;

    /**
     * Seed an outbox row holding the finalised record's envelope, encrypted,
     * under the record's id, with the columns given in place of the row's own,
     * and return the id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array<string, int|string|null>  $columns
     * @return string
     */
    protected function enqueue(#[\SensitiveParameter] FinalisedRecord $record, array $columns = []): string
    {
        $id = $record->record->id;

        $this->seedOutboxRow($id, $this->encryptedEnvelope($record), $columns);

        return $id;
    }

    /**
     * The finalised record's envelope, encrypted as a string by the
     * application's encrypter, as the outbox holds it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     */
    protected function encryptedEnvelope(#[\SensitiveParameter] FinalisedRecord $record): string
    {
        return app(StringEncrypter::class)->encryptString(app(EnvelopeCodec::class)->encode($record));
    }

    /**
     * The record finalised once by the application's finaliser, a captured
     * record of an approved invoice when none is given.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    protected function finalisedRecord(?AuditRecord $record = null): FinalisedRecord
    {
        return app(RecordFinaliser::class)->finalise($record ?? RecordFactory::captured());
    }

    /**
     * Put the application in outbox mode, so a record is inserted in the outbox
     * and reaches its store only when it is drained.
     *
     * @return void
     */
    protected function outboxModeOn(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);
    }
}
