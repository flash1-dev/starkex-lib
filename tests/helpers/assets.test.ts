/**
 * Unit tests for helpers/assets.
 */

import expect from 'expect';
import Big from 'big.js';

import {
  SYNTHETIC_ASSET_ID_MAP,
  COLLATERAL_ASSET_ID_BY_NETWORK_ID,
} from '../../src/constants';
import {
  Flash1Asset,
  Flash1Market,
  NetworkId,
  StarkwareOrderSide,
} from '../../src/types';

// Module under test.
import {
  fromQuantums,
  getStarkwareAmounts,
  getStarkwareLimitFeeAmount,
  toQuantumsExact,
  toQuantumsRoundDown,
  toQuantumsRoundUp,
} from '../../src/helpers/assets';

describe('assets helpers', () => {

  describe('fromQuantums()', () => {

    it('converts a number of quantums to a human-readable amount', () => {
      expect(
        fromQuantums('1000', Flash1Asset.ETH),
      ).toBe('0.00001');
    });

    it('throws if the asset is unknown', () => {
      expect(() => {
        fromQuantums('1000', 'UNKNOWN' as Flash1Asset);
      }).toThrow('Unknown asset');
    });
  });

  describe('getStarkwareAmounts()', () => {

    it('converts order params to Starkware order params', () => {
      expect(
        getStarkwareAmounts({
          market: Flash1Market.BTC_USD,
          side: StarkwareOrderSide.SELL,
          humanSize: '250.0000000001',
          humanPrice: '1.23456789',
        }, NetworkId.GOERLI),
      ).toStrictEqual({
        quantumsAmountSynthetic: '2500000000001',
        quantumsAmountCollateral: '308641972',
        assetIdSynthetic: SYNTHETIC_ASSET_ID_MAP[Flash1Asset.BTC],
        assetIdCollateral: COLLATERAL_ASSET_ID_BY_NETWORK_ID[NetworkId.GOERLI],
        isBuyingSynthetic: false,
      });
    });

    it('converts order params to Starkware order params', () => {
      expect(
        getStarkwareAmounts({
          market: Flash1Market.BTC_USD,
          side: StarkwareOrderSide.BUY,
          humanSize: '22.3784',
          humanPrice: '21647.585000000003',
        }, NetworkId.GOERLI),
      ).toStrictEqual({
        quantumsAmountSynthetic: '223784000000',
        quantumsAmountCollateral: '484438316165',
        assetIdSynthetic: SYNTHETIC_ASSET_ID_MAP[Flash1Asset.BTC],
        assetIdCollateral: COLLATERAL_ASSET_ID_BY_NETWORK_ID[NetworkId.GOERLI],
        isBuyingSynthetic: true,
      });
    });

    it('converts order params with a quote amount instead of price', () => {
      expect(
        getStarkwareAmounts({
          market: Flash1Market.BTC_USD,
          side: StarkwareOrderSide.SELL,
          humanSize: '250.0000000001',
          humanQuoteAmount: '308.641972',
        }, NetworkId.GOERLI),
      ).toStrictEqual({
        quantumsAmountSynthetic: '2500000000001',
        quantumsAmountCollateral: '308641972',
        assetIdSynthetic: SYNTHETIC_ASSET_ID_MAP[Flash1Asset.BTC],
        assetIdCollateral: COLLATERAL_ASSET_ID_BY_NETWORK_ID[NetworkId.GOERLI],
        isBuyingSynthetic: false,
      });
    });

    it('throws if the order size is not a multiple of the Starkware quantum', () => {
      expect(() => {
        getStarkwareAmounts({
          market: Flash1Market.BTC_USD,
          side: StarkwareOrderSide.SELL,
          humanSize: '250.00000000001',
          humanPrice: '1.23456789',
        }, NetworkId.GOERLI);
      }).toThrow('not a multiple of the quantum size');
    });

    it('throws if the quote amount is given and is not a multiple of the Starkware quantum', () => {
      expect(() => {
        getStarkwareAmounts({
          market: Flash1Market.BTC_USD,
          side: StarkwareOrderSide.SELL,
          humanSize: '250.0000000001',
          humanQuoteAmount: '308.64197212',
        }, NetworkId.GOERLI);
      }).toThrow('not a multiple of the quantum size');
    });
  });

  describe('toQuantumsExact()', () => {

    it('converts a human readable amount to an integer number of quantums', () => {
      expect(
        toQuantumsExact('12.0000003', Flash1Asset.BTC),
      ).toBe('120000003000');
    });

    it('throws if the amount does not divide evenly by the quantum size', () => {
      expect(() => {
        toQuantumsExact('12.00000000031', Flash1Asset.BTC);
      }).toThrow('not a multiple of the quantum size');
    });
  });

  describe('toQuantumsRoundDown()', () => {

    it('converts a human readable amount to an integer number of quantums', () => {
      expect(
        toQuantumsRoundDown('12.0000003', Flash1Asset.BTC),
      ).toBe('120000003000');
    });

    it('rounds down if the amount does not divide evenly by the quantum size', () => {
      expect(
        toQuantumsRoundDown('12.00000031', Flash1Asset.BTC),
      ).toBe('120000003100');
    });
  });

  describe('toQuantumsRoundUp()', () => {

    it('converts a human readable amount to an integer number of quantums', () => {
      expect(
        toQuantumsRoundUp('12.0000003', Flash1Asset.BTC),
      ).toBe('120000003000');
    });

    it('rounds up if the amount does not divide evenly by the quantum size', () => {
      expect(
        toQuantumsRoundUp('12.00000031', Flash1Asset.BTC),
      ).toBe('120000003100');
    });
  });

  describe('getStarkwareLimitFeeAmount()', () => {

    it('converts the order limit fee as expected (edge case)', () => {
      expect(
        getStarkwareLimitFeeAmount(
          '0.000001999999999999999999999999999999999999999999',
          '50750272151',
        ),
      ).toBe('50751');
    });
  });
});
