package info.willdspann.crypto.util

import java.nio.charset.StandardCharsets

import org.bouncycastle.crypto.digests.{SHA512Digest, SHA512tDigest}
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter

object HmacUtils {

    /**
     * Generates an HMAC of the given message using the provided key and the
     * SHA-512 cryptographic hash.
     */
    def hmacSha512(message: String, keyBytes: Array[Byte]): Array[Byte] = {
        val hmacDigest = new SHA512Digest()
        val key = new KeyParameter(keyBytes)
        val hmacGenerator = new HMac(hmacDigest)
        hmacGenerator.init(key)
        val messageBytes = message.getBytes(StandardCharsets.UTF_8)
        hmacGenerator.update(messageBytes, 0, messageBytes.length)
        val hmacOutput = new Array[Byte](64)
        hmacGenerator.doFinal(hmacOutput, 0)

        hmacOutput
    }

    /**
     * Generate a truncated HMAC of the given message using the provided key, truncated to
     * `hashSizeBytes` bytes in length. HMAC is performed using the SHA-512 cryptographic
     * hash, followed by a final SHA-512/t hash of this HMAC using the desired length
     * (e.g., SHA-512/64 for an 8-byte HMAC).
     *
     * TODO: Implement a version that performs the HMAC itself using SHA-512/t, instead of
     *   a two-step process.
     */
    def hmacSha512t(message: String, keyBytes: Array[Byte], hashSizeBytes: Int): Array[Byte] = {
        val hmac = hmacSha512(message, keyBytes)

        // Truncate HMAC to hashSizeBits w/ a final SHA-512/t
        val truncatedDigest = new SHA512tDigest(hashSizeBytes * 8)
        truncatedDigest.update(hmac, 0, hmac.length)
        val truncatedHmac = new Array[Byte](hashSizeBytes)
        truncatedDigest.doFinal(truncatedHmac, 0)

        truncatedHmac
    }
}
