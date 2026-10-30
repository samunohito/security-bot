import { expect, it } from 'vitest';
import { formatDigest } from '../src/social/digest';

it('期間・分割番号・出典を含めて文字数内に項目単位で分割する', () => {
  const entries = ['a', 'b', 'c'].map((id) => ({ id, text: `${id} ${'影響'.repeat(35)} https://example.com/${id}` }));
  const pages = formatDigest(entries, { start: 0, end: 21600000 }, 240);
  expect(pages.length).toBeGreaterThan(1);
  expect(pages.flatMap((page) => page.ids)).toEqual(['a', 'b', 'c']);
  expect(pages.every((page) => [...page.text].length <= 240)).toBe(true);
  expect(pages[0]?.text).toContain('1/');
  expect(pages[0]?.text).toContain('https://example.com/a');
});
it('単独でも収まらない項目を黙って切り捨てない', () => {
  expect(() => formatDigest([{ id: 'a', text: '長'.repeat(1000) }], { start: 0, end: 21600000 }, 200)).toThrow(
    'digest_item_too_long:a',
  );
});
it('項目のない期間は投稿を作らない', () => {
  expect(formatDigest([], { start: 0, end: 21600000 }, 200)).toEqual([]);
});
it('全体の分割数を考慮した事前検査で番号の桁増加を検知する', () => {
  const entry = { id: 'a', text: 'a'.repeat(135) };
  expect(formatDigest([entry], { start: 0, end: 21600000 }, 200)).toHaveLength(1);
  expect(() => formatDigest([entry], { start: 0, end: 21600000 }, 200, 10)).toThrow('digest_item_too_long:a');
});

it('上限ちょうどの項目を受け付け、1文字超過は保留対象にする', () => {
  const entry = { id: 'a', text: '😀'.repeat(136) };
  const expected = `NVD Highまとめ 1970-01-01 09:00〜1970-01-01 15:00 JST (1/1)\n\n・${entry.text}\n\n#NVD`;
  expect([...expected]).toHaveLength(200);
  expect(formatDigest([entry], { start: 0, end: 21600000 }, 200)).toEqual([{ ids: ['a'], text: expected }]);
  expect(() => formatDigest([{ ...entry, text: `${entry.text}超` }], { start: 0, end: 21600000 }, 200)).toThrow(
    'digest_item_too_long:a',
  );
});

it('4件で打ち切らず上限まで詰め、同じ項目でも小さい上限では分割する', () => {
  const entries = Array.from({ length: 6 }, (_, index) => ({ id: String(index), text: '項'.repeat(90) }));
  const window = { start: 0, end: 21600000 };
  expect(formatDigest(entries, window, 800).map((page) => page.ids)).toEqual([['0', '1', '2', '3', '4', '5']]);
  expect(formatDigest(entries, window, 300).map((page) => page.ids)).toEqual([
    ['0', '1'],
    ['2', '3'],
    ['4', '5'],
  ]);
});
