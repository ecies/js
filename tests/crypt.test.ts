import { expect } from 'chai';
import hello from '../src/index'

describe('Hello', function () {
    it('should return Hello {word}!', function () {
        let result = hello('a');
        expect(result).to.equal('Hello a!');

    });
});
