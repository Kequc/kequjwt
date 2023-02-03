import { createHmac } from 'crypto';

type Payload = { [name: string]: any };

enum ERROR {
    PAYLOAD_INVALID = 'Payload must be an object',
    KEY_REQUIRED = 'Key is required',
    TOKEN_REQUIRED = 'Token is required',
    TOKEN_INVALID = 'Token format invalid',
    SIGNATURE_FAILED = 'Signature verification failed',
    TOKEN_NBF = 'Token not yet active',
    TOKEN_EXP = 'Token expired'
}

function encode (payload: Payload, key: string): string {
    validate(ERROR.PAYLOAD_INVALID, typeof payload !== 'object' || payload === null || Array.isArray(payload));
    validate(ERROR.KEY_REQUIRED, typeof key !== 'string' || !key);

    const encoded = base64Encode(payload);
    const signature = sign(encoded, key);

    return `${encoded}.${signature}`;
}

function decode (token: string, key: string): Payload {
    validate(ERROR.TOKEN_REQUIRED, typeof token !== 'string' || !token);
    validate(ERROR.KEY_REQUIRED, typeof key !== 'string' || !key);

    const segments = token.split('.');
    const signature = segments.pop();
    const encoded = segments.pop();

    validate(ERROR.TOKEN_INVALID, !encoded || !signature);
    validate(ERROR.SIGNATURE_FAILED, signature !== sign(encoded!, key));

    const payload = base64Decode(encoded!);
    const time = Math.floor(Date.now() / 1000);

    validate(ERROR.TOKEN_EXP, typeof payload.exp === 'number' && time >= payload.exp);
    validate(ERROR.TOKEN_NBF, typeof payload.nbf === 'number' && time < payload.nbf);

    return payload;
}

const header = base64Encode({ typ: 'JWT', alg: 'HS256' });

export default {
    encode,
    decode,
    header,
    ERROR
};

function sign (encoded: string, key: string): string {
    return createHmac('sha256', key).update(`${header}.${encoded}`).digest('base64url');
}

function base64Encode (payload: Payload): string {
    return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function base64Decode (encoded: string): Payload {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString());
}

function validate (message: ERROR, value: boolean): void {
    if (value) throw new Error(message);
}
