import crypto = require('crypto');

module.exports = function(key: Buffer, data: Buffer, algorithm:string = 'SHA1'): string{
	let hmac = crypto.createHmac(algorithm,key);
	hmac.update(data);
	return hmac.digest('hex');
}