'use strict';

var base32 = require('thirty-two');
var hmac = require('../dist/HMAC');
var HOTP = require('../dist/HOTP');
var TOTP = require('../dist/TOTP');
var GoogleAuthenticator = require('../dist/GoogleAuthenticator');

describe('Base32 encoding Algorithm',function(){
	var plainText = '12345678901234567890';
	var encodedText = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	it('should encode into base32',function(){
		var b32Str = base32.encode(plainText).toString();
		expect(b32Str).toBeDefined();
		expect(b32Str).toEqual(encodedText);
	});
	it('should decode from base32',function(){
		var str = base32.decode(encodedText).toString();
		expect(str).toBeDefined();
		expect(str).toEqual(plainText);
	});
});

describe('HMAC-SHA1 Algorithm', function() {
	it('should caculate empty hash', function() {
		var hash = hmac(new Buffer(''), new Buffer(''));
		expect(hash).toBeDefined();
		expect(hash.length).toBe(40);
		expect(hash).toEqual('fbdb1d1b18aa6c08324b7d64b71fb76370690e1d');
	});
	it('should caculate non-empty hash', function() {
		var hash = hmac(new Buffer('key'), new Buffer('The quick brown fox jumps over the lazy dog'));
		expect(hash).toBeDefined();
		expect(hash.length).toBe(40);
		expect(hash).toEqual('de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9');
	});
});

describe('HMAC-based One-time Password Algorithm',function(){
	var key = '12345678901234567890';
	var hotp = new HOTP();
	it('should generate counter (0)',function(){
		var decimal = hotp.generate(key,0);
		expect(decimal).toBeDefined();
		expect(decimal).toEqual(1284755224);
	});
	it('should generate counter (1)',function(){
		var decimal = hotp.generate(key,1);
		expect(decimal).toBeDefined();
		expect(decimal).toEqual(1094287082);
	});
	it('should generate counter (8)',function(){
		var decimal = hotp.generate(key,8);
		expect(decimal).toBeDefined();
		expect(decimal).toEqual(673399871);
	});
	it('should generate counter (9)',function(){
		var decimal = hotp.generate(key,9);
		expect(decimal).toBeDefined();
		expect(decimal).toEqual(645520489);
	});
	it('should generate counter otp (0)',function(){
		var otp = hotp.generateOTP(key,0);
		expect(otp).toBeDefined();
		expect(otp).toEqual('755224');
	});
	it('should generate counter otp (1)',function(){
		var otp = hotp.generateOTP(key,1);
		expect(otp).toBeDefined();
		expect(otp).toEqual('287082');
	});
	
	it('should generate counter otp (8)',function(){
		var otp = hotp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('399871');
	});
	it('should generate counter otp (9)',function(){
		var otp = hotp.generateOTP(key,9);
		expect(otp).toBeDefined();
		expect(otp).toEqual('520489');
	});
});
describe('Time-based One-time Password Algorithm',function(){
	var key = '12345678901234567890';
	it('should generate counter otp (1970-01-01T00:00:59)',function(){
		var totp = new TOTP(59);
		var otp = totp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('94287082');
	});
	it('should generate counter otp (2005-03-18T01:58:29)',function(){
		var totp = new TOTP(1111111109);
		var otp = totp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('07081804');
	});
	it('should generate counter otp (2005-03-18T01:58:31)',function(){
		var totp = new TOTP(1111111111);
		var otp = totp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('14050471');
	});
	it('should generate counter otp (2009-02-13T23:31:30)',function(){
		var totp = new TOTP(1234567890);
		var otp = totp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('89005924');
	});
	it('should generate counter otp (2033-05-18T03:33:20)',function(){
		var totp = new TOTP(2000000000);
		var otp = totp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('69279037');
	});
	it('should generate counter otp (2603-10-11T11:33:20)',function(){
		var totp = new TOTP(20000000000);
		var otp = totp.generateOTP(key,8);
		expect(otp).toBeDefined();
		expect(otp).toEqual('65353130');
	});
	it('should generate counter otp (now)',function(){
		var totp = new TOTP();
		var otp = totp.generateOTP(key);
		expect(otp).toBeDefined();
	});
});

describe('Google Authenticator One-time Password Algorithm',function(){
	var key = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	var authenticator = new GoogleAuthenticator();
	it('should generate OTP',function(){
		var otp = authenticator.generateOTP(key);
		expect(otp).toBeDefined();
		console.log(`\n\tOTP: ${otp}`);
	});
	it('should generate new secret (base32 encoded)',function(){
		var secret = authenticator.generateNewBase32Secret();
		expect(secret).toBeDefined();
		console.log(`\n\tsecret: ${secret}`);
	});
	it('should generate key URI',function(){
		var uri = authenticator.generateKeyUri('user@example.com',key,'Test');
		expect(uri).toBeDefined();
		console.log(`\n\tkeyURI: ${uri}`);
	});
	it('should generate QRCode URI',function(){
		var uri = authenticator.generateQrCode('user@example.com',key,'Test');
		expect(uri).toBeDefined();
		console.log(`\n\tQRCode: ${uri}`);
	});
});