var base32 = require('thirty-two');
var uid = require('uid-safe');
var TOTP = require('./TOTP');
/**
 * Google implementation of the authenticator(base on Time-based One-time Password Algorithm,RFC 6238)
 */
module.exports = class {
	protected totp = new TOTP();
	/**
	 * @param {string} b32key - expects the K secret key to be entered (or supplied in a QR code) in base-32 encoding
	 */
	generateOTP(b32key: string): string {
		let decodedKey = base32.decode(b32key.toUpperCase());
		return this.totp.generateOTP(decodedKey);
	}
	verify(token: string, b32key: string): boolean {
		let expectedToken = this.generateOTP(b32key);
		return (token === expectedToken);
	}
	/**
	 * generate new secret key
	 * 
	 * @return {string} - secret key in base-32 encoding
	 */
	generateNewBase32Secret(minlength: number = 20): string {
		return base32.encode(uid.sync(minlength).toUpperCase());
	}
	/**
	 * generate the key uri
	 * 
	 * @param {string} user - the user for this account
	 * @param {string|undefined} secret - secret in base32
	 * @param {string} issuer - the provider or service managing that account
	 * @return {string} representation of key uri 
	 * ex: otpauth://totp/issuer:user@host?secret=xxx&issuer=yyy
	 * ex: otpauth://totp/user@host?secret=xxx
	 */
	generateKeyUri(user: string, secret: string,issuer?: string): string {
		//Google authenticator doesn't like equal signs
		secret = secret.replace(/=/g,'');
		if (typeof issuer !== 'undefined'){
			let _issuer = issuer.charAt(0).toUpperCase() + issuer.substr(1);
			return `otpauth://totp/${_issuer}:${user}?secret=${secret.toUpperCase()}&issuer=${_issuer}`;
		}
		return `otpauth://totp/${user}?secret=${secret.toUpperCase()}`;
	}
	/**
	 * generate the QR Code Url
	 */
	generateQrCode(user: string, secret: string,issuer?: string,size: number = 250): string {
		let keyUri = this.generateKeyUri(user, secret, issuer);
		return `https://chart.googleapis.com/chart?cht=qr&chs=${size}x${size}&chl=${encodeURIComponent(keyUri)}`;
	}

}