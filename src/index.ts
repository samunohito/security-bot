import bundledConfig from '../bot.config.json';
import { loadConfig } from './config';
import { adminRequest } from './admin';
import { Bot, type BotEnv } from './pipeline';

function createBot(env: BotEnv) {
  return new Bot(env, loadConfig(bundledConfig, env));
}
export default {
  async fetch(request: Request, env: BotEnv): Promise<Response> {
    return (
      (await adminRequest(
        request,
        createBot(env),
        typeof env.ADMIN_TOKEN === 'string' ? env.ADMIN_TOKEN : undefined,
      )) ?? new Response('Not found', { status: 404 })
    );
  },
  async scheduled(_event: ScheduledController, env: BotEnv) {
    await createBot(env).tick();
  },
  async queue(batch: MessageBatch<{ id: string }>, env: BotEnv) {
    const bot = createBot(env);
    for (const message of batch.messages) {
      if (typeof message.body?.id !== 'string') {
        message.ack();
        continue;
      }
      try {
        await bot.runJob(message.body.id);
        message.ack();
      } catch {
        message.retry({ delaySeconds: 60 });
      }
    }
    await bot.flush(Date.now());
  },
};
