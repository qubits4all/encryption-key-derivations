package info.willdspann.crypto

import javax.security.auth.Destroyable

import org.apache.commons.codec.binary.Base64

import org.bouncycastle.crypto.generators.Argon2BytesGenerator

import info.willdspann.crypto.util.{SensitiveBytes, SensitiveString}

class ClientSideEncryptionContext(keyGenerationSecret: SensitiveString) extends Destroyable {
    private val keyGenSecret: SensitiveBytes = SensitiveBytes(
        Base64.decodeBase64(keyGenerationSecret.toString)
    )
    private val prkLen: Int = 32      // PRK size (bytes)
    private var prk: DestroyableKey = _

    def generateKeySet(passphrase: SensitiveString): CryptoKeySet = {
        this.prk = deriveBasePRK(passphrase)
        ???
    }

    /*
     * TODO: Use HKDF (HMAC-based Key Derivation Function) to generate the actual base
     *   pseudo-random key (PRK) from the Argon2-produced PRK.
     */
    private def deriveBasePRK(passphrase: SensitiveString): DestroyableKey = {
        val argon2Generator = new Argon2BytesGenerator()
        val argon2Parameters = new PasswordBasedKeyDerivationContext(prkLen).argon2ParametersFor(keyGenSecret)
        argon2Generator.init(argon2Parameters)
        argon2Parameters.clear()  // clear passed password & salt

        val derivedPrkBytes: Array[Byte] = new Array[Byte](prkLen)
        argon2Generator.generateBytes(passphrase.chars, derivedPrkBytes)
        new DestroyableAesKey(derivedPrkBytes)
    }

    /*
     * TODO: Use HKDF to generate other derived keys by name, using the provided 'keyName'
     *   as associated-data, using the base PRK produced by deriveBasePRK().
     */
    private def generateKeyByName(keyName: String): DestroyableKey = {
        ???
    }
}
