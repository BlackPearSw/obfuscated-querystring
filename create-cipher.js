const crypto = require('crypto');

function sizes(cipher) {
  for (let nkey = 1, niv = 0;;) {
    try {
      crypto.createCipheriv(cipher, '.'.repeat(nkey), '.'.repeat(niv));
      return [nkey, niv];
    } catch (e) {
      if (/invalid iv length/i.test(e.message)) niv += 1;
      else if (/invalid key length/i.test(e.message)) nkey += 1;
      else throw e;
    }
  }
}

//Replicates the EVP_BytesToKey function used by deprecated crypto.createCipher
//with the digest algorithm set to MD5, one iteration, and no salt
module.exports = function compute(cipher, passphrase) {
  let [nkey, niv] = sizes(cipher);
  for (let key = '', iv = '', p = '';;) {
    const h = crypto.createHash('md5');
    h.update(p, 'hex');
    h.update(passphrase);
    p = h.digest('hex');
    let n, i = 0;
    n = Math.min(p.length-i, 2*nkey);
    nkey -= n/2, key += p.slice(i, i+n), i += n;
    n = Math.min(p.length-i, 2*niv);
    niv -= n/2, iv += p.slice(i, i+n), i += n;
    if (nkey+niv === 0) return [key, iv];
  }
}
