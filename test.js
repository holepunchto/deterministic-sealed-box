const sodium = require('sodium-universal')
const test = require('brittle')
const b4a = require('b4a')

const seal = require('./')

test('simple', t => {
  const recipient = seal.keyPair()
  const message = b4a.from('some data to encrypt')
  const key = b4a.alloc(32, 0xff)

  const payload = seal.encrypt(message, recipient.publicKey, key)

  t.is(payload.byteLength, message.byteLength + sodium.crypto_box_SEALBYTES)

  const decrypted = seal.decrypt(payload, recipient)

  t.alike(decrypted, message)
})

test('decrypt in place', t => {
  const recipient = seal.keyPair()
  const message = b4a.from('some data to encrypt')
  const key = b4a.alloc(32, 0xff)

  const payload = seal.encrypt(message, recipient.publicKey, key)

  t.is(payload.byteLength, message.byteLength + sodium.crypto_box_SEALBYTES)

  const decrypted = seal.decrypt(payload, recipient, payload.subarray(0, message.byteLength))

  t.alike(decrypted, message)
})

test('throw with no hash key', t => {
  const recipient = seal.keyPair()
  const message = b4a.from('some data to encrypt')

  t.exception(() => seal.encrypt(message, recipient.publicKey, null), /No hash key provided/)
})
