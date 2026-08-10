// The po-av01j.133.8 shape: an SDK client in a module binding, invoked
// through a CHAINED attribute path. The TypeChecker resolves the receiver
// fine; the site was invisible because "create" was in neither method
// allowlist, so the single most valuable surface (the LLM invocation) never
// became a packet.
import OpenAI from 'openai';

const client = new OpenAI();

export async function ask(prompt: string): Promise<unknown> {
  return client.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  });
}
