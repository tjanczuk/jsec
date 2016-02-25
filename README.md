jsec: secure your JSON
====

With the *jsec* package you can easily encrypt, sign, and base64-url encode any JSON-serializable data. Encoded data can be safely transmitted through untrusted channels or persisted. 

Key features: 

* You can use any signature and encryption algorithm, as long as it is HMAC-SHA256 and AES-256-CBC, respectively.
* You can maintain a set of accepted signature/encryption keysets which helps arrange key rollover.
* Encrypted and signed data is base64-url encoded for ease of trasmission over HTTP.

### Installation

```
npm install jsec
```

### Encoding

```javascript
var crypto = require('crypto');
var jsec = require('jsec');

var keyset = {
    // keyset identifier
    id: '1',

    // signature key - any length
    skey: crypto.randomBytes(20),

    // encryption key - must be 32 bytes
    ekey: crypto.randomBytes(32)
};

// payload to protect - any JSON-serializable structure
var payload = {
    hello: 'world',
    foo: 12
};

console.log(jsec.encode(payload, keyset));
```

### Decoding

```javascript
var jsec = require('jsec');

// map of accepted keysets
var keysets = {
    '1': {
        // signature key - same as before
        skey: new Buffer(...),

        // encryption key - must be 32 bytes and same as before
        ekey: new Buffer(...)
    },
    '2': {
        // ... another accepted keyset 
    }
};

var encoded = ... // the base64-url encoded string 

console.log(jsec.decode(encoded, keysets));

// returns an object with 2 properties: 
// .id - the keyset id used to decode the payload
// .payload - JSON-deserialized plaintext payload
```
