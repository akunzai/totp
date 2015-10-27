# TypeScript One Time Password library (HOTP,TOTP,Google Authenticator)
One Time Password library that working in Node.js environment

## Requirement

```sh
npm install -g tsd gulp
```

## Build

```sh
npm install
tsd install
gulp build
```

## Run Unit Test

```sh
gulp test
```

## Usage

```javascript
var GoogleAuthenticator = require('dist/GoogleAuthenticator');
var authenticator = new GoogleAuthenticator();
var key = authenticator.generateNewBase32Secret();
// generate QRCode image URL (through google chart api)
var url = authenticator.generateQrCode('user@example.com',key,'Test');
console.log('open following url to add new shared secret to Google Authenticator:\n' + url);
// generate one time password
var otp = authenticator.generateOTP(key);
console.log('generated one-time-password:' + otp);
```

## Reference

- [HOTP](https://tools.ietf.org/html/rfc4226)
- [TOTP](https://tools.ietf.org/html/rfc6238)
- [GoogleAuthenticator](https://github.com/google/google-authenticator)