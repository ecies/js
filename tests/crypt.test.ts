import { expect } from 'chai';
import { remove0x, decodeHex, getValidSecret } from '../src/utils'

describe('test string <-> buffer utils ', () => {
    it('should remove 0x', () => {
        expect(remove0x('0x0011')).to.equal('0011')
        expect(remove0x('0X0022')).to.equal('0022')
    });

    it('should convert hex to buffer', () => {
        let decoded = decodeHex('0x0011')
        expect(decoded.equals(Buffer.from([0, 0x11]))).to.be.true;
    });
});
