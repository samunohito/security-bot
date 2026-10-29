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
  const entry = { id: 'a', text: 'a'.repeat(134) };
  expect(formatDigest([entry], { start: 0, end: 21600000 }, 200)).toHaveLength(1);
  expect(() => formatDigest([entry], { start: 0, end: 21600000 }, 200, 10)).toThrow('digest_item_too_long:a');
});
