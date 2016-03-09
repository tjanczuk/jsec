var base64url = require('base64-url')
    , assert = require('assert')
    , crypto = require('crypto')
    ;

exports.encode = function (payload, keyset) {
    assert.ok(payload);
    assert.ok(keyset);
    assert.ok(Buffer.isBuffer(keyset.skey));
    assert.ok(Buffer.isBuffer(keyset.ekey));
    assert.equal(keyset.ekey.length, 32, 'Encryption key must be 32 bytes long.')
    assert.equal(typeof keyset.id, 'string');

    var header = new Buffer(JSON.stringify({ kid: keyset.id }));
    var plaintext_payload = new Buffer(JSON.stringify(payload));
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv('aes-256-cbc', keyset.ekey, iv);
    var encrypted_payload = Buffer.concat([cipher.update(plaintext_payload), cipher.final()]);
    var signature = crypto.createHmac('sha256', keyset.skey).update(encrypted_payload).update(iv).digest();
    return [base64url.encode(header), base64url.encode(encrypted_payload), base64url.encode(iv), base64url.encode(signature)].join('.');
};

exports.decode = function (payload, keysets) {
    assert.equal(typeof payload, 'string');
    assert.ok(keysets);

    var header, encrypted_payload, iv, sig;
    try {
        var tokens = payload.split('.');
        header = JSON.parse(new Buffer(base64url.unescape(tokens[0]), 'base64').toString('utf8'));
        encrypted_payload = new Buffer(base64url.unescape(tokens[1]), 'base64');
        iv = new Buffer(base64url.unescape(tokens[2]), 'base64');
        sig = new Buffer(base64url.unescape(tokens[3]), 'base64');
    }
    catch (e) {
        throw new Error('Malformed payload.')
    }
    var keyset = keysets[header.kid];
    if (!keyset) throw new Error('Payload protected with unsupported keyset.');
    try {
        var actual_sig = crypto.createHmac('sha256', keyset.skey).update(encrypted_payload).update(iv).digest();
        if (typeof actual_sig.compare === 'function') {
            if (0 !== actual_sig.compare(sig)) throw new Error('Signatures do not match.');
        }
        else {
            if (actual_sig.length !== sig.length) throw new Error('Signatures do not match.');
            for (var k = 0; k < actual_sig.length; k++)
                if (actual_sig[k] !== sig[k]) throw new Error('Signatures do not match.');
        }
    }
    catch (e) {
        throw new Error('Signature verification failed.');
    }
    try {
        var cipher = crypto.createDecipheriv('aes-256-cbc', keyset.ekey, iv);
        var payload = JSON.parse(Buffer.concat([cipher.update(encrypted_payload), cipher.final()]).toString('utf8'));
        return { id: header.kid, payload: payload };
    }
    catch (e) {
        throw new Error('Payload decryption failed.')
    }
};
