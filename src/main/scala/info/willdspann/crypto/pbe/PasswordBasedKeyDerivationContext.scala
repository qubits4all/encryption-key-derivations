package info.willdspann.crypto.pbe

import java.security.SecureRandom

import info.willdspann.crypto.util.SensitiveBytes
import org.bouncycastle.crypto.params.Argon2Parameters

class PasswordBasedKeyDerivationContext(private val keySizeBytes: Int, private val saltSizeBytes: Int) {
    private val secureRandom: SecureRandom = new SecureRandom()

    private val argon2Type: Int = Argon2Parameters.ARGON2_id
    private val argon2Version: Int = Argon2Parameters.ARGON2_VERSION_13

    private def defaultArgon2ParametersBuilder: Argon2Parameters.Builder = {
        new Argon2Parameters.Builder(argon2Type).withVersion(argon2Version)
    }
    private def argon2ParametersBuilderFor(
        iterations: Int,
        memoryUsagePowOf2: Int,
        parallelism: Int): Argon2Parameters.Builder =
    {
        defaultArgon2ParametersBuilder.withIterations(iterations)
            .withMemoryPowOfTwo(memoryUsagePowOf2)
            .withParallelism(parallelism)
    }

    def argon2DefaultParameters(): Argon2Parameters = {
        val saltBytes: Array[Byte] = new Array[Byte](saltSizeBytes)
        secureRandom.nextBytes(saltBytes)

        defaultArgon2ParametersBuilder.withSalt(saltBytes)
            .build()
    }

    def argon2DefaultParametersFor(salt: SensitiveBytes): Argon2Parameters = {
        defaultArgon2ParametersBuilder.withSalt(salt.bytes)
            .build()
    }

    /*
     * NOTE: The 'secret' parameter is an optional "pepper" secret key, used for keyed
     *   hash generation with Argon2. Using such a secret value in client-side code will
     *   likely be problematic, due to insufficient means to secure this sensitive value.
     */
    def argon2ParametersFor(secret: SensitiveBytes): Argon2Parameters = {
        generateArgon2Parameters(secret)
    }

    def argon2ParametersFor(secret: SensitiveBytes, salt: SensitiveBytes): Argon2Parameters = {
        defaultArgon2ParametersBuilder.withSalt(salt.bytes)
            .withSecret(secret.bytes)
            .build()
    }

    private def generateArgon2Parameters(secret: SensitiveBytes): Argon2Parameters = {
        val saltBytes: Array[Byte] = new Array[Byte](saltSizeBytes)
        secureRandom.nextBytes(saltBytes)

        buildArgon2Parameters(secret, SensitiveBytes(saltBytes))
    }

    private def buildArgon2Parameters(secret: SensitiveBytes, salt: SensitiveBytes): Argon2Parameters = {
        defaultArgon2ParametersBuilder.withSalt(salt.bytes)
            .withSecret(secret.bytes)
            .build()
    }
}
