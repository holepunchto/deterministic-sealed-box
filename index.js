const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const [NS_SEED] = crypto.namespace('deterministic-sealed-box', 1)

module.exports = {
  encrypt,
  decrypt,
  keyPair
}

function encrypt (message, recipient, hashKey) {
  const seed = deriveSeed(message)
  const ephemeral = keyPair(seed)

  const sealed = b4a.alloc(sodium.crypto_box_SEALBYTES + message.byteLength)
  const box = sealed.subarray(sodium.crypto_box_PUBLICKEYBYTES)

  sealed.set(ephemeral.publicKey)

  const nonce = deriveNonce(ephemeral.publicKey, recipient)

  sodium.crypto_box_easy(box, message, nonce, recipient, ephemeral.secretKey)

  return sealed
}

function decrypt (payload, recipient, output) {
  if (!output) output = b4a.alloc(payload.byteLength - sodium.crypto_box_SEALBYTES)

  if (!sodium.crypto_box_seal_open(output, payload, recipient.publicKey, recipient.secretKey)) {
    throw new Error('Failed to open sealed box')
  }

  return output
}

function keyPair (seed) {
  const secretKey = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
  const publicKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)

  if (seed) {
    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
  } else {
    sodium.crypto_box_keypair(publicKey, secretKey)
  }

  return {
    publicKey,
    secretKey
  }
}

function deriveSeed (message, hashKey) {
  const seed = b4a.alloc(sodium.crypto_box_SEEDBYTES)
  sodium.crypto_generichash_batch(seed, [NS_SEED, message], hashKey)

  return seed
}

// libsodium compatible for crypto_seal_box_open
function deriveNonce (epk, rpk) {
  const nonce = b4a.alloc(sodium.crypto_box_NONCEBYTES)
  sodium.crypto_generichash_batch(nonce, [epk, rpk])

  return nonce
}
