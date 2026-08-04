// Background-job registration surfaces (G3, po-av01j.4): bullmq dispatches
// (one bounded by a per-job timeout option, one bare), a bullmq Worker
// handler registration, and a node-cron schedule. The untyped lookalike at
// the bottom must NOT be kinded: detection is type-driven, abstain rather
// than guess.
import { Queue, Worker } from 'bullmq';
import cron from 'node-cron';

const emails = new Queue('emails', { connection: {} });

export async function enqueueWelcome(userId: number): Promise<void> {
  // Bounded dispatch: the job carries its own timeout option.
  await emails.add('welcome', { userId }, { timeout: 5000 });
}

export async function enqueueDigest(userId: number): Promise<void> {
  // Bare dispatch: no bound of any kind.
  await emails.add('digest', { userId });
}

export function startWorker(): Worker {
  // Handler registration: the processor closure is the job body.
  return new Worker('emails', async (job: unknown) => {
    return job;
  });
}

export function startCron(): void {
  cron.schedule('*/5 * * * *', () => {
    void emails.add('poll', {});
  });
}

export function notAJob(registry: any): void {
  // Lookalike on an untyped receiver: never guessed at.
  registry.schedule('*/5 * * * *', () => undefined);
}
