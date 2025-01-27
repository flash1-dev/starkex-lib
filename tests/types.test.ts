import { Flash1Asset, Flash1Market } from '../src/types';
import { ASSET_RESOLUTION, SYNTHETIC_ASSET_MAP } from '../src/constants';
import expect from 'expect';

describe('Flash1Market', () => {
  const cases = Object.entries(Flash1Market); // returns[[ 'BTC_USD', 'BTC-USD' ], ...]
  const edgeCases = [Flash1Market.BTC_USD]; // handle non-matching left-hand component
  it('correctly maps enum values', () => {
    cases.filter(([_, v]) => !edgeCases.includes(v)).forEach(([k, v]) => {
      const enumKeyParts = k.split('_');
      const enumValParts = v.split('-');
      expect(enumKeyParts).toEqual(enumValParts);
      expect(enumKeyParts.length).toBe(2);
      expect(enumValParts.length).toBe(2);
    });
  });

  it('correctly maps enum values of edge cases', () => {
    cases.filter(([_, v]) => edgeCases.includes(v)).forEach(([k, v]) => {
      const enumKeyParts = k.split('_');
      const enumValParts = v.split('-');
      expect(enumKeyParts.slice(1)).toEqual(enumValParts.slice(1));
      expect(enumKeyParts.length).toBe(2);
      expect(enumValParts.length).toBe(2);
    });
  });

});

describe('SYNTHETIC_ASSET_MAP', () => {
  it.skip('contains all assets in Flash1Market', () => { // TODO: unskip when we know our market list
    expect(Object.keys(SYNTHETIC_ASSET_MAP)).toEqual(Object.values(Flash1Market));
  });

  it('contains all markets in TOTAL_CORE_MARKETS_ARRAY', () => {
    const assets = Object.keys(ASSET_RESOLUTION);
    expect(Object.values(SYNTHETIC_ASSET_MAP).every((x) => assets.includes(x))).toBeTruthy();
  });

  it.skip('contains all assets in Flash1Asset', () => { // TODO: unskip when we know our asset list
    const assets = Object.values(Flash1Asset).filter((x) => x !== Flash1Asset.USDT);
    expect(Object.values(SYNTHETIC_ASSET_MAP)).toEqual(assets);
  });
});
