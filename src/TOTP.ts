var HOTP = require('./HOTP');
/**
 * Time-based One-time Password Algorithm (RFC 6238)
 */
module.exports = class {
	protected hotp;
	constructor(protected T1?:number,protected T0: number = 0,protected algorithm: string = 'SHA1'){
		this.hotp = new HOTP(algorithm);
	}
	/**
	 * TOTP = HOTP(SecretKey, TC)
	 * 
	 * @param key: the shared secret, HEX encoded
	 */
	public generate(key: string): number {
		let tc = this.getTimeCounter();
		return this.hotp.generate(key,tc);
	}
	/**
	 * TOTP-Value = TOTP mod 10^d, where d is the desired number of digits of the one-time password.
	 *
	 * @param key: the shared secret, HEX encoded
	 * @param responseLength: number of digits to return
	 */
	public generateOTP(key: string, responseLength: number = 6): string {
		let totp = this.generate(key);
		let otp = totp % Math.pow(10, responseLength);
		let result = otp.toString();
		// pad leading zero
		while (result.length < responseLength) {
			result = '0' + result;
		}
		return result;
	}
	public verify(token: string, key: string, responseLength: number = 6): boolean {
		let expectedToken = this.generateOTP(key, responseLength);
		return (token === expectedToken);
	}
	/**
	 * TC = (unixtime(now) - unixtime(T0)) / TS
	 */
	protected getTimeCounter(timeStep: number = 30): number {
		// defaults are the Unix epoch as T0 and 30 seconds as TI
		let t1 = this.T1 || (new Date().getTime() / 1000);
		return Math.floor((t1 - this.T0) / timeStep);
	}
}