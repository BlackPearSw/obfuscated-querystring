const querystring = require('querystring');
const crypto = require('crypto');
const createCipher = require('./create-cipher');

const ALGORITHM = 'aes256';
const PLAINTEXTENCODING = 'utf8';
const CIPHERTEXTENCODING = 'hex';
const DELIMITER = '|';
const ENCRYPTEDKEY = 'enc';

function encrypt(plaintext, encryptionKey){
    let [key, iv] = createCipher(ALGORITHM, encryptionKey);
    key = Buffer.from(`${key}`, 'hex');
    iv  = Buffer.from(`${iv}`, 'hex');

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    return cipher.update(plaintext, PLAINTEXTENCODING, CIPHERTEXTENCODING) + cipher.final(CIPHERTEXTENCODING);
}

function decrypt(ciphertext, encryptionKey){
    let [key, iv] = createCipher(ALGORITHM, encryptionKey);
    key = Buffer.from(`${key}`, 'hex');
    iv  = Buffer.from(`${iv}`, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
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
        Object.assign(allKeys, clarifiedKeys);

        // remove the encrypted key
        delete allKeys[ENCRYPTEDKEY];
    }

    return querystring.unescape(querystring.stringify(allKeys));
}

module.exports.obfuscate = obfuscate;
module.exports.clarify = clarify;
