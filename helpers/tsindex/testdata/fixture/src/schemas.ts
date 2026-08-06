import z from 'zodlike';

// Pure schema construction. Resolves to the external package `zodlike`, but
// performs no I/O -- tsindex must not emit these as call sites.
export const userName = z.string().trim().min(1).describe('name');
export const userId = z.string().uuid().optional();
export const userShape = z.object({ name: userName, id: userId });
