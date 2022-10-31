import { createHmac } from 'crypto';

type TPayload = { [name: string]: any };

const header = base64Encode({ typ: 'JWT', alg: 'HS256' });

enum ERROR {
    PAYLOAD_INVALID = 'Payload must be an object',
    KEY_REQUIRED = 'Key is required',
    TOKEN_REQUIRED = 'Token is required',
    TOKEN_INVALID = 'Token format invalid',
    SIGNATURE_FAILED = 'Signature verification failed',
    TOKEN_NBF = 'Token not yet active',
    TOKEN_EXP = 'Token expired'
}

function encode (payload: TPayload, key: string): string {
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
        throw new Error(ERROR.PAYLOAD_INVALID);
    }
    if (typeof key !== 'string' || !key) {
        throw new Error(ERROR.KEY_REQUIRED);
    }

    const encoded = base64Encode(payload);
    const signature = sign(encoded, key);

    return `${encoded}.${signature}`;
}

function decode (token: string, key: string): TPayload {
    if (typeof token !== 'string' || !token) {
        throw new Error(ERROR.TOKEN_REQUIRED);
    }
    if (typeof key !== 'string' || !key) {
        throw new Error(ERROR.KEY_REQUIRED);
    }

    const segments = token.split('.');

    if (segments.length !== 2 || !segments[0] || !segments[1]) {
        throw new Error(ERROR.TOKEN_INVALID);
    }

    const [encoded, signature] = segments;

    if (signature !== sign(encoded, key)) {
        throw new Error(ERROR.SIGNATURE_FAILED);
    }

    const payload = base64Decode(encoded);
    const time = Math.floor(Date.now() / 1000);

    if (typeof payload.nbf === 'number' && time < payload.nbf) {
        throw new Error(ERROR.TOKEN_NBF);
    }
    if (typeof payload.exp === 'number' && time >= payload.exp) {
        throw new Error(ERROR.TOKEN_EXP);
    }

    return payload;
}

export default {
    encode,
    decode,
    header,
    ERROR
};

function sign (encoded: string, key: string): string {
    return createHmac('sha256', key).update(`${header}.${encoded}`).digest('base64url');
}

function base64Encode (payload: TPayload): string {
    return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function base64Decode (encoded: string): TPayload {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString());
}
