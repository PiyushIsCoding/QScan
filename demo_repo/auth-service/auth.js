const crypto = require('crypto');
const KEY_BITS = 2048;
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: KEY_BITS });
const sign = crypto.createSign("RSA-SHA256");
