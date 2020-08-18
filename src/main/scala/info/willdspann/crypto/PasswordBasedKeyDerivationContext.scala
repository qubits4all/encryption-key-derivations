package info.willdspann.crypto

import java.security.SecureRandom

import org.bouncycastle.crypto.params.Argon2Parameters

import info.willdspann.crypto.util.{SensitiveBytes, SensitiveString}

class PasswordBasedKeyDerivationContext(private val keySizeBytes: Int) {
    private val secureRandom: SecureRandom = new SecureRandom()

    private val argon2Type: Int = Argon2Parameters.ARGON2_id
    private val argon2Version: Int = Argon2Parameters.ARGON2_VERSION_13

    private def getArgon2Builder: Argon2Parameters.Builder = {
        new Argon2Parameters.Builder(argon2Type).withVersion(argon2Version)
    }

    /*
     * NOTE: The 'secret' parameter is an optional "pepper" secret key, used for keyed
     *   hash generation with Argon2. Using such a secret value in client-side code will
     *   likely be problematic, due to insufficient means to secure this sensitive value.g
     */
    def argon2ParametersFor(secret: SensitiveBytes): Argon2Parameters = {
        generateArgon2Parameters(secret)
    }

    def argon2ParametersFor(secret: SensitiveBytes, salt: SensitiveBytes): Argon2Parameters = {
        getArgon2Builder.withSalt(salt.bytes)
            .withSecret(secret.bytes)
            .build()
    }

    private def generateArgon2Parameters(secret: SensitiveBytes): Argon2Parameters = {
        val saltBytes: Array[Byte] = new Array[Byte](keySizeBytes)
        secureRandom.nextBytes(saltBytes)

        buildArgon2Parameters(secret, SensitiveBytes(saltBytes))
    }

    private def buildArgon2Parameters(secret: SensitiveBytes, salt: SensitiveBytes): Argon2Parameters = {
        getArgon2Builder.withSalt(salt.bytes)
            .withSecret(secret.bytes)
            .build()
    }
}
