import type { Environment, SourceConfig } from '../config';
import type { Fetcher } from '../http';
import { kevProvider } from './kev';
import { nvdProvider } from './nvd';
import type { SourceOptions, SourceProvider } from './provider';
import { rssProvider } from './rss';

/** 収集元設定に対応するプロバイダーを生成する。 */
export function sourceProvider(
  config: SourceConfig,
  env: Environment = {},
  fetcher: Fetcher = fetch,
  options: SourceOptions = {},
): SourceProvider {
  switch (config.kind) {
    case 'rss':
      return rssProvider(config, fetcher);
    case 'kev':
      return kevProvider(config, fetcher, options);
    case 'nvd':
      return nvdProvider(config, env, fetcher, options);
  }
}
