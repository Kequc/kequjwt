# kequjwt

A very simple implementation of headless jwt tokens. Useful for when you just want signed payloads to store and decode. Ensures the token is free of tampering and within a valid date range.

## Usage

```
npm i kequjwt
```

```typescript
import jwt from 'kequjwt';

const payload = { hello: 'world' };
const key = 'secret';

const token = jwt.encode(payload, key);
// ~> eyJoZWxsbyI6IndvcmxkIn0.bqxXg9VwcbXKoiWtp-osd0WKPX307RjcN7EuXbdq-CE

jwt.decode(token, key);
// ~> { hello: 'world' }
```

Decode will throw an error if the token is invalid or unable to be verified. The generated token is headless meaning it contains only the `payload` and `signature` segments of the jwt.

## JWT invalidation

To set a not before or expiry date use `'exp'` and `'nbf'` measured in seconds.

```typescript
const time = Math.floor(Date.now() / 1000);

const payload = {
    hello: 'world',
    nbf: time,
    exp: time + (60 * 60) // 1 hour
};
```

## JWT header

The header is equivalent to base64url encoded `'{ typ: "JWT", alg: "HS256" }'` and can be accessed using `jwt.header` if needed for any reason.

```typescript
const fullToken = `${jwt.header}.${token}`;
```

## Suggestions

Please use a secure key, generate something 10-20 characters long then switch a few characters around by hand. Don't store keys in your repository if you can help it.
