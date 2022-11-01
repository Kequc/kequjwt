import assert from 'assert';
import 'kequtest';
import jwt from '../src/kequjwt';

function plusHours(count: number): number {
    return Math.floor(Date.now() / 1000) + (60 * 60 * count);
}

const EXAMPLES = [{
    payload: { hello: 'world1' },
    token: 'eyJoZWxsbyI6IndvcmxkMSJ9.aGKCoDnKydHynAU05v0Qzje-wo_gKTy18eFLoOLQJWM',
    key: 'secret1'
}, {
    payload: { hello: 'world2' },
    token: 'eyJoZWxsbyI6IndvcmxkMiJ9.2ZEISQ_0nix2nUwSHcUZbY1sWCt_5smRjg6zn1zADD0',
    key: 'secret2'
}];

describe('kequjwt', () => {
    it('exposes header', () => {
        assert.strictEqual(jwt.header, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9');
    });

    it('encodes a token', () => {
        for (const { payload, token, key } of EXAMPLES) {
            assert.strictEqual(jwt.encode(payload, key), token);
        }
    });

    it('decodes a token', () => {
        for (const { payload, token, key } of EXAMPLES) {
            assert.deepStrictEqual(jwt.decode(token, key), payload);
        }
    });

    it('fails to decode using invalid key', () => {
        const message = jwt.ERROR.SIGNATURE_FAILED;

        for (const { token, key } of EXAMPLES) {
            assert.throws(() => jwt.decode(token, key + '-wrong'), { message });
        }
    });

    it('fails to decode tampered token', () => {
        const message = jwt.ERROR.SIGNATURE_FAILED;
        const key = EXAMPLES[0].key;
        const signature = EXAMPLES[0].token.split('.')[1];
        const wrongPayload = EXAMPLES[1].token.split('.')[0];
        const token = `${wrongPayload}.${signature}`;

        assert.throws(() => jwt.decode(token, key), { message });
    });

    it('fails to decode frankentoken', () => {
        const message = jwt.ERROR.SIGNATURE_FAILED;
        const key = EXAMPLES[0].key;
        const wrongSignature = EXAMPLES[1].token.split('.')[1];
        const payload = EXAMPLES[0].token.split('.')[0];
        const token = `${payload}.${wrongSignature}`;

        assert.throws(() => jwt.decode(token, key), { message });
    });

    it('decodes timed token', () => {
        const payload = { nbf: plusHours(-1), exp: plusHours(1) };
        const key = 'secret';
        const token = jwt.encode(payload, key);

        assert.deepStrictEqual(jwt.decode(token, key), payload);
    })

    it('fails to decode expired token', () => {
        const payload = { exp: plusHours(-1) };
        const key = 'secret';
        const token = jwt.encode(payload, key);
        const message = jwt.ERROR.TOKEN_EXP;

        assert.throws(() => jwt.decode(token, key), { message });
    });

    it('fails to decode not yet valid token', () => {
        const payload = { nbf: plusHours(1) };
        const key = 'secret';
        const token = jwt.encode(payload, key);
        const message = jwt.ERROR.TOKEN_NBF;

        assert.throws(() => jwt.decode(token, key), { message });
    });
});
