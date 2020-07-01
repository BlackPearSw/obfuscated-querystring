const querystring = require('querystring');
const crypto = require('crypto');
const _ = require('lodash');

const ALGORITHM = 'aes256';
const PLAINTEXTENCODING = 'utf8';
const CIPHERTEXTENCODING = 'hex';
const DELIMITER = '|';
const ENCRYPTEDKEY = 'enc';
const IV = Buffer.alloc(16);

function encrypt(plaintext, encryptionKey){
    const cipher = crypto.createCipheriv(ALGORITHM, crypto.createHash("sha256").update(encryptionKey).digest(), IV);
    return cipher.update(plaintext, PLAINTEXTENCODING, CIPHERTEXTENCODING) + cipher.final(CIPHERTEXTENCODING);
}

function decrypt(ciphertext, encryptionKey){
    const decipher = crypto.createDecipheriv(ALGORITHM, crypto.createHash("sha256").update(encryptionKey).digest(), IV);
    return decipher.update(ciphertext, CIPHERTEXTENCODING, PLAINTEXTENCODING) + decipher.final(PLAINTEXTENCODING);
}

function obfuscate(s, options){
    if (!options){
        throw new Error('options undefined');
    }

    const allKeys = querystring.parse(s);
    const obfuscatedKeys = options.obfuscate.reduce((prev, key)=>{
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

    const allKeys = querystring.parse(s);
    const encrypted = allKeys[ENCRYPTEDKEY];

    if (encrypted){
        // get the encryption key
        const encryptionKeyName = encrypted.split('|')[0];
        const encryptionKey = options.encryptionKeys[encryptionKeyName];

        // decipher the value
        const ciphertext = encrypted.split('|')[1];
        const plaintext = decrypt(ciphertext, encryptionKey);
        const clarifiedKeys = querystring.parse(plaintext);

        // add the clarified keys
        _.merge(allKeys, clarifiedKeys);

        // remove the encrypted key
        delete allKeys[ENCRYPTEDKEY];
    }

    return querystring.unescape(querystring.stringify(allKeys));
}

module.exports.obfuscate = obfuscate;
module.exports.clarify = clarify;