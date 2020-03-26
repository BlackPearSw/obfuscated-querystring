const querystring = require('querystring');
const crypto = require('crypto');
const _ = require('lodash');

const ALGORITHM = 'aes256';
const PLAINTEXTENCODING = 'utf8';
const CIPHERTEXTENCODING = 'hex';
const DELIMITER = '|';
const ENCRYPTEDKEY = 'enc';

function encrypt(plaintext, encryptionKey){
    let cipher = crypto.createCipher(ALGORITHM, encryptionKey);
    return cipher.update(plaintext, PLAINTEXTENCODING, CIPHERTEXTENCODING) + cipher.final(CIPHERTEXTENCODING);
}

function decrypt(ciphertext, encryptionKey){
    let decipher = crypto.createDecipher(ALGORITHM, encryptionKey);
    return decipher.update(ciphertext, CIPHERTEXTENCODING, PLAINTEXTENCODING) + decipher.final(PLAINTEXTENCODING);
}

function obfuscate(s, options){
    if (!options){
        throw new Error('options undefined');
    }

    let allKeys = querystring.parse(s);
    let obfuscatedKeys = options.obfuscate.reduce((prev, key)=>{
        if (allKeys[key]){
            prev = prev || {};
            prev[key]=allKeys[key];
            delete allKeys[key];
        }
        return prev;
    }, undefined);

    if (obfuscatedKeys){
        allKeys[ENCRYPTEDKEY] = options.encryptionKey.name + DELIMITER + encrypt(querystring.stringify(obfuscatedKeys), options.encryptionKey.value)
    }

    return querystring.unescape(querystring.stringify(allKeys));
}

function clarify(s, options){
    if (!options){
        throw new Error('options undefined');
    }

    let allKeys = querystring.parse(s);
    let encrypted = allKeys[ENCRYPTEDKEY];

    if (encrypted){
        // get the encryption key
        let encryptionKeyName = encrypted.split('|')[0];
        let encryptionKey = options.encryptionKeys[encryptionKeyName];

        // decipher the value
        let ciphertext = encrypted.split('|')[1];
        let plaintext = decrypt(ciphertext, encryptionKey);
        let clarifiedKeys = querystring.parse(plaintext);

        // add the clarified keys
        _.merge(allKeys, clarifiedKeys);

        // remove the encrypted key
        delete allKeys[ENCRYPTEDKEY];
    }

    return querystring.unescape(querystring.stringify(allKeys));
}

module.exports.obfuscate = obfuscate;
module.exports.clarify = clarify;