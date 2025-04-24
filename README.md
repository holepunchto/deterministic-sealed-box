# deterministic-sealed-box

## Usage

```js
const seal = require('deterministic-sealed-box')

// sender side

const message = Buffer.from('som data to seal')
const fixedKey = Buffer.alloc(32, 0xff) // should be fixed for seal to be deterministic

const payload = seal.encrypt(message, recipientPublicKey, fixedKey)

// receiver side

const message = seal.decrypt(message, recipientKeyPair)
```

## API

#### `const keyPair = seal.keyPair([seed])`

Generate a key pair, optionally pass a `seed`

#### `const sealed = seal.encrypt(message, recipient, fixedKey)`

Create a sealed box. `recipient` should be the recipients public key. `fixedKey` is 32 bytes.

The output `sealed` is deterministic over `message`, `recipient` and `fixedKey`.

#### `const message = seal.decrypt(message, recipientKeyPair)` 

Open a sealed box. `recipientKeyPair` should be the `{ publicKey, secretKey }` corresponding to the public key used to create the seal.

Can also be opened using `sodium.crypto_box_seal_open` API.

## License

Apache-2.0
