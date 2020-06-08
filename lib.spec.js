const clarify = require('./lib').clarify;
const obfuscate = require('./lib').obfuscate;

const testCases = require('./sample/cases.json');
const testKeys  = require('./sample/keys.json');
require('chai').should();

describe('lib', () => {
    describe('clarify', ()=>{
        testCases.forEach((testCase) => {
            it(`${testCase.ciphertext} => ${testCase.plaintext}`, ()=>{
                const options = {
                    encryptionKeys: testKeys
                };

                clarify(testCase.ciphertext, options).should.equal(testCase.plaintext);
            });
        });
    });

    describe('obfuscate', ()=>{
        testCases.forEach((testCase) => {
            it(`${testCase.plaintext} => ${testCase.ciphertext}`, ()=>{
                const options = {
                    obfuscate: testCase.obfuscate || [],
                    encryptionKey: {
                        name: testCase.key,
                        value: testKeys[testCase.key]
                    }
                };

                obfuscate(testCase.plaintext, options).should.equal(testCase.ciphertext);
            });
        });
    });
});
