var assert = require('assert')
    , jsec = require('../')
    , crypto = require('crypto')
    ;

var keysets = {
    '1': {
        id: '1',
        skey: new Buffer('siganturekey'),
        ekey: crypto.randomBytes(32)
    },
    '2': {
        id: '1',
        skey: new Buffer('siganturekey'),
        ekey: crypto.randomBytes(48)
    },
};

var payload = {
    hello: 'world',
    foo: 'bar'
};

describe('encode', function () {

    it('throws without payload', function () {
        assert.throws(function () {
            jsec.encode();
        }, Error);
    });

    it('throws without keyset', function () {
        assert.throws(function () {
            jsec.encode({});
        }, Error);
    });

    it('throws without encryption key', function () {
        assert.throws(function () {
            jsec.encode({}, { skey: new Buffer() });
        }, Error);
    });

    it('throws without signing key', function () {
        assert.throws(function () {
            jsec.encode({}, { ekey: new Buffer() });
        }, Error);
    });

    it('throws with signing key that is not Buffer', function () {
        assert.throws(function () {
            jsec.encode({}, { skey: 'foo', ekey: new Buffer() });
        }, Error);
    });

    it('throws with encryption key that is not Buffer', function () {
        assert.throws(function () {
            jsec.encode({}, { ekey: 'foo', skey: new Buffer() });
        }, Error);
    });

    it('encodes to string', function () {
        assert.equal(typeof jsec.encode(payload, keysets['1']), 'string');
    });

    it('fails to encode with encryption key other than 32 bytes long', function () {
        assert.throws(function () {
            jsec.encode(payload, keysets['2']);
        }, /encryption key must be 32 bytes long/i);
    });

});

describe('decode', function () {

    it('throws without payload', function () {
        assert.throws(function () {
            jsec.decode();
        }, Error);
    });

    it('throws without keysets', function () {
        assert.throws(function () {
            jsec.decode("");
        }, Error);
    });

    it('throws without non-string payload', function () {
        assert.throws(function () {
            jsec.decode({},{});
        }, Error);
    });

    it('decodes from string', function () {
        var encoded = jsec.encode(payload, keysets['1']);
        var result = jsec.decode(encoded, keysets);
        assert.ok(result);
        assert.equal(result.id, '1');
        assert.equal(typeof result.payload, 'object');
        assert.equal(result.payload.hello, 'world');
        assert.equal(result.payload.foo, 'bar');
    });

    it('fails with malformed input', function () {
        assert.throws(function () {
            jsec.decode("foo", keysets);
        }, /malformed payload/i);
    });

    it('fails with invalid signature', function () {
        var encoded = jsec.encode(payload, keysets['1']).split('.');
        encoded[1] = 'evil';
        encoded = encoded.join('.');
        assert.throws(function () {
            jsec.decode(encoded, keysets);
        }, /signature verification failed/i);
    });

    it('fails with invalid encryption key', function () {
        var encoded = jsec.encode(payload, keysets['1']);
        assert.throws(function () {
            jsec.decode(encoded, { '1': { id: '1', skey: keysets['1'].skey, ekey: crypto.randomBytes(32) }});
        }, /payload decryption failed/i);
    });

    it('fails with unsupported keyset', function () {
        var encoded = jsec.encode(payload, keysets['1']);
        assert.throws(function () {
            jsec.decode(encoded, {});
        }, /payload protected with unsupported keyset/i);
    });

});
