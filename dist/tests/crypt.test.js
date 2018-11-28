import hello from '../src/index';
import { expect } from 'chai';
import 'mocha';
describe('Hello', function () {
    it('should return hello a', function () {
        var result = hello('a');
        expect(result).to.be('helloa');
    });
});
//# sourceMappingURL=crypt.test.js.map