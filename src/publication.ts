/** CVSSの最大値を、未評価・Low/Medium・High・Criticalの段階へ変換する。 */
export function severityLevel(scores: { score: number }[]): number {
  const score = Math.max(0, ...scores.map((value) => value.score));

  return score >= 9 ? 3 : score >= 7 ? 2 : score > 0 ? 1 : 0;
}

/** 重大度、情報源の範囲、緊急性から発信方法を選ぶ。 */
export function publicationRoute(level: number, nvdOnly: boolean, urgent: boolean): 'individual' | 'digest' {
  return nvdOnly && level === 2 && !urgent ? 'digest' : 'individual';
}

/** 日本時間を基準に、直近で閉じたまとめ対象期間を返す。 */
export function digestWindow(now: number, intervalSeconds: number): { start: number; end: number } {
  const interval = intervalSeconds * 1000;
  const offset = 9 * 3600000;
  const end = Math.floor((now + offset) / interval) * interval - offset;

  return { start: end - interval, end };
}
