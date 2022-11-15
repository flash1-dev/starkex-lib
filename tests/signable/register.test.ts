/**
 * Unit tests for signable/withdrawal.ts.
 */

import expect from 'expect';
import _ from 'lodash';

import {
    KeyPairWithYCoordinate,
    NetworkId,
    StarkwareRegistration
} from '../../src/types';
import { mutateHexStringAt } from '../util';

// Module under test.
import { SignableRegistration } from '../../src/signable';
import { BN } from 'bn.js';
import { stripHexPrefix } from '../../src/lib/util';

// Mock params.
const mockKeyPair: KeyPairWithYCoordinate = {
    publicKey: '3b865a18323b8d147a12c556bfb1d502516c325b1477a23ba6c77af31f020fd',
    publicKeyYCoordinate: '211496e5e8ccf71930aebbfb7e815807acbfd0021f17f8b3944a3ed5f06c27',
    privateKey: '58c7d5a90b1776bde86ebac077e053ed85b0f7164f53b080304a531947f46e3',
}
const mockRegistration: StarkwareRegistration = {
    ethKey: '0x9aB2f5bBdc3D991CBDb5D834de69707921F15B35',
    starkKey: mockKeyPair.publicKey,
};
const mockSignature = (
    "0x072312cf31dc432afa04e7f4fc097bb465d83285dc948d98dbe0e76207f082d203a047914f558701e02024396e9b55cd9abe7308118b8eed83602637eb3cf63d00211496e5e8ccf71930aebbfb7e815807acbfd0021f17f8b3944a3ed5f06c27"
);

describe('SignableRegistration', () => {

    describe('sign()', () => {

        it('signs a registration', async () => {
            const signature = await SignableRegistration
                .fromRegistration(mockRegistration.ethKey, mockRegistration.starkKey, NetworkId.GOERLI)
                .sign(mockKeyPair);
            expect(signature).toEqual(mockSignature);
        });

        it('correct signature length', async () => {
            const signature = await SignableRegistration
                .fromRegistration(mockRegistration.ethKey, mockRegistration.starkKey, NetworkId.GOERLI)
                .sign(mockKeyPair);
            expect(new BN(stripHexPrefix(signature), 'hex').byteLength()).toEqual(32 * 3);
        });
    });

    describe.skip('verifySignature()', () => {

        it('returns true for a valid signature', async () => {
            const result = await SignableRegistration
                .fromRegistration(mockRegistration.ethKey, mockRegistration.starkKey, NetworkId.GOERLI)
                .verifySignature(mockSignature, mockKeyPair.publicKey);
            expect(result).toBe(true);
        });

        it('returns false for an invalid signature', async () => {
            // Mutate a single character in r.
            await Promise.all(_.range(1, 4).map(async (i) => {
                const badSignature: string = mutateHexStringAt(mockSignature, i);
                const result = await SignableRegistration
                    .fromRegistration(mockRegistration.ethKey, mockRegistration.starkKey, NetworkId.GOERLI)
                    .verifySignature(badSignature, mockKeyPair.publicKey);
                expect(result).toBe(false);
            }));

            // Mutate a single character in s.
            await Promise.all(_.range(1, 4).map(async (i) => {
                const badSignature: string = mutateHexStringAt(mockSignature, i + 64);
                const result = await SignableRegistration
                    .fromRegistration(mockRegistration.ethKey, mockRegistration.starkKey, NetworkId.GOERLI)
                    .verifySignature(badSignature, mockKeyPair.publicKey);
                expect(result).toBe(false);
            }));
        });
    });
});
