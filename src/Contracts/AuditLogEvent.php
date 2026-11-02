<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Audit log event contract: marks the events the package dispatches itself, so
 * a listener can tell them apart, and so the package never maps one of its own
 * events to a record of itself.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuditLogEvent {}
