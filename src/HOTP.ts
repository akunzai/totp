var hmac = require('./HMAC');
/**
 * HMAC-based One-time Password Algorithm (RFC 4226)
 */
module.exports = class {
	constructor(protected algorithm: string = 'SHA1'){
	}
	/**
	 * HOTP(K,C) = Truncate(HMAC(K,C)) & 0x7FFFFFFF
	 */
	public generate(key: string, counter: number = 0): number{
		let msg = this.intToBytes(counter);
		let hex = hmac(new Buffer(key),new Buffer(msg),this.algorithm);
		let bytes = this.hexToBytes(hex);
		return this.truncate(bytes);
	}
	/**
	 * HOTP-Value = HOTP(K,C) mod 10^d, where d is the desired number of digits
	 */
	public generateOTP(key: string, counter: number = 0, responseLength: number = 6): string {
		let hotp = this.generate(key,counter);
		let otp = hotp % Math.pow(10, responseLength);
		let result = otp.toString();
		// pad leading zero
		while (result.length < responseLength) {
			result = '0' + result;
		}
		return result;
	}
	public  verify(token: string, key: string, counter: number = 0,responseLength: number = 6): boolean{
		let expectedToken = this.generateOTP(key,counter,responseLength);
		return (token === expectedToken);
	}
	protected truncate(bytes: Array<number>): number {
		let offset = bytes[bytes.length - 1] & 0xf;
		let binary =
			((bytes[offset] & 0x7f) << 24) |
			((bytes[offset + 1] & 0xff) << 16) |
			((bytes[offset + 2] & 0xff) << 8) |
			(bytes[offset + 3] & 0xff);
		return binary;
	}
	/**
	 * convert a hex value to a byte array
	 * 
	 */
	protected hexToBytes(hex: string): Array<number> {
		let bytes: Array<number> = [];
		for (let c = 0; c < hex.length; c += 2) {
			bytes.push(parseInt(hex.substr(c, 2), 16));
		}
		return bytes;
	}
	/**
	 * convert an integer to a byte array
	 * 
	 */
	protected intToBytes(input: number): Array<number> {
		let bytes: Array<number> = [];
		for (let i = 7 ; i >= 0; i--) {
			bytes[i] = input & 0xff;
			input = input >> 8;
		}
		return bytes;
	}
}