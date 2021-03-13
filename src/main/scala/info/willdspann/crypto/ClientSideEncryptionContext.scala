package info.willdspann.crypto

import java.nio.charset.StandardCharsets
import java.security.SecureRandom

import javax.security.auth.Destroyable

import org.bouncycastle.crypto.generators.{Argon2BytesGenerator, HKDFBytesGenerator}
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.params.HKDFParameters

import info.willdspann.crypto.model.NamedKeyType
import info.willdspann.crypto.pbe.PasswordBasedKeyDerivationContext
import info.willdspann.crypto.util.{SensitiveBytes, SensitiveString}

class ClientSideEncryptionContext() extends Destroyable {
    private val localRandom: ThreadLocal[SecureRandom] = ThreadLocal.withInitial(
        () => new SecureRandom()
    )
    private val prkLen: Int = 32      // PRK size (bytes)
    private val saltLen: Int = 16     // HDKF salt size (bytes)
    private var prk: DestroyablePasswordBasedKeyProfile = _
    private var hmacKey: DestroyablePasswordBasedKeyProfile = _

    def generateKeySet(passphrase: SensitiveString): CryptoKeySet = {
        this.hmacKey = deriveHmacKey(passphrase)
        this.prk = derivePasswordBasedPRK(passphrase)

        val profileKey = generateKeyByName(NamedKeyType.ProfileAESEncryption)
        val protectedKey = generateKeyByName(NamedKeyType.ProtectedProfileAESEncryption)

        CryptoKeySet(
            hmacKey.passwordBasedHkdfPrk,
            profileKey,
            protectedKey,
            prk.hkdfSalt,
            Some(prk.argon2Salt)
        )
    }

    def regenerateKeySet(
        passphrase: SensitiveString,
        argon2Salt: SensitiveBytes,
        hkdfSalt: SensitiveBytes
    ): CryptoKeySet = {
        this.hmacKey = rederiveHmacKey(passphrase, argon2Salt, hkdfSalt)
        this.prk = rederivePasswordBasedPRK(passphrase, argon2Salt, hkdfSalt)

        val profileKey = generateKeyByName(NamedKeyType.ProfileAESEncryption)
        val protectedKey = generateKeyByName(NamedKeyType.ProtectedProfileAESEncryption)

        CryptoKeySet(
            hmacKey.passwordBasedHkdfPrk,
            profileKey,
            protectedKey,
            hkdfSalt,
            Some(argon2Salt)
        )
    }

    def generateKeyByName(keyType: NamedKeyType): DestroyableKey = {
        val hkdfParams = hkdfExpandParametersFor(prk.passwordBasedHkdfPrk, keyType.name)

        val prkGenerator = new HKDFBytesGenerator(new SHA512Digest())
        prkGenerator.init(hkdfParams)
        val prkBytes = new Array[Byte](prkLen)
        prkGenerator.generateBytes(prkBytes, 0, prkBytes.length)

        keyType match {
            case NamedKeyType.ProfileAESEncryption | NamedKeyType.ProtectedProfileAESEncryption =>
                new DestroyableAesKey(prkBytes)

            case NamedKeyType.TOTPSecretSeed =>
                new DestroyableTotpKey(prkBytes)

            case NamedKeyType.HMACProfile =>
                new DestroyableHmacKey(prkBytes)
        }
    }

    private def hkdfExpandParametersFor(pbePrk: DestroyableKey, keyName: String): HKDFParameters = {
        HKDFParameters.skipExtractParameters(
            prk.passwordBasedHkdfPrk.getEncoded,
            keyName.getBytes(StandardCharsets.UTF_8)
        )
    }


    /**
     * Generates a password-based pseudo-random key (PRK) using the Argon2 password hash, followed
     * by HKDF with a random salt.
     *
     * HMAC-based Key Derivation Function (HKDF) takes the high-entropy but non-uniform pseudorandom
     * key (PRK), derived from the given passphrase using Argon2, and produces a uniformly-distributed
     * high-entropy base PRK suitable for use as symmetric encryption key (e.g., with AES).
     */
    def derivePasswordBasedPRK(passphrase: SensitiveString): DestroyablePasswordBasedKeyProfile = {
        // Derive a non-uniform but high-entropy PRK from given passphrase using Argon2.
        val argon2Prk = derivePasswordBasedArgon2PRK(passphrase)

        // Derive a uniformly-distributed PRK from the non-uniform Argon2-generated PRK.
        val hkdfParams = hkdfExtractParametersFor(
            argon2Prk.passwordBasedPrk,
            NamedKeyType.PasswordBasedEncryptionPRK.name
        )
        val prkGenerator = new HKDFBytesGenerator(new SHA512Digest())
        prkGenerator.init(hkdfParams)
        val prkBytes = new Array[Byte](prkLen)
        prkGenerator.generateBytes(prkBytes, 0, prkBytes.length)

        val pbeKey = DestroyablePasswordBasedKeyProfile(
            new DestroyableAesKey(prkBytes),
            argon2Prk.argon2Salt.copyOf(),
            SensitiveBytes(hkdfParams.getSalt)
        )
        argon2Prk.destroy()

        pbeKey
    }

    private def derivePasswordBasedArgon2PRK(passphrase: SensitiveString): DestroyableArgon2KeyProfile = {
        val argon2Parameters = new PasswordBasedKeyDerivationContext(prkLen, saltLen)
            .argon2DefaultParameters()
        val argon2Generator = new Argon2BytesGenerator()
        argon2Generator.init(argon2Parameters)

        // Derive a non-uniform but high-entropy PRK from given passphrase using Argon2.
        val derivedPrkBytes: Array[Byte] = new Array[Byte](prkLen)
        argon2Generator.generateBytes(passphrase.chars, derivedPrkBytes)
        passphrase.destroy()

        val argon2Prk = DestroyableArgon2KeyProfile(
            SensitiveBytes(derivedPrkBytes),
            SensitiveBytes(argon2Parameters.getSalt)
        )

        argon2Prk
    }


    def rederivePasswordBasedPRK(
        passphrase: SensitiveString,
        argon2Salt: SensitiveBytes,
        hkdfSalt: SensitiveBytes
    ): DestroyablePasswordBasedKeyProfile = {
        // Derive a non-uniform but high-entropy PRK from given passphrase using Argon2.
        val argon2Prk = rederivePasswordBasedArgon2PRK(passphrase, argon2Salt)

        // Derive a uniformly-distributed PRK from the non-uniform Argon2-generated PRK.
        val hkdfParams = hkdfExtractParametersFor(
            argon2Prk.passwordBasedPrk,
            hkdfSalt,
            NamedKeyType.PasswordBasedEncryptionPRK.name
        )
        val prkGenerator = new HKDFBytesGenerator(new SHA512Digest())
        prkGenerator.init(hkdfParams)
        val prkBytes = new Array[Byte](prkLen)
        prkGenerator.generateBytes(prkBytes, 0, prkBytes.length)

        val pbeKey = DestroyablePasswordBasedKeyProfile(
            new DestroyableAesKey(prkBytes),
            argon2Prk.argon2Salt.copyOf(),
            hkdfSalt
        )
        argon2Prk.destroy()

        pbeKey
    }

    private def rederivePasswordBasedArgon2PRK(
        passphrase: SensitiveString,
        argon2Salt: SensitiveBytes
    ): DestroyableArgon2KeyProfile = {
        val argon2Parameters = new PasswordBasedKeyDerivationContext(prkLen, saltLen)
            .argon2DefaultParametersFor(argon2Salt)
        val argon2Generator = new Argon2BytesGenerator()
        argon2Generator.init(argon2Parameters)

        // Derive a non-uniform but high-entropy PRK from given passphrase using Argon2.
        val derivedPrkBytes: Array[Byte] = new Array[Byte](prkLen)
        argon2Generator.generateBytes(passphrase.chars, derivedPrkBytes)
        passphrase.destroy()

        val argon2Prk = DestroyableArgon2KeyProfile(
            SensitiveBytes(derivedPrkBytes),
            argon2Salt
        )

        argon2Prk
    }


    def deriveHmacKey(passphrase: SensitiveString): DestroyablePasswordBasedKeyProfile = {
        val argon2Prk = derivePasswordBasedArgon2PRK(passphrase)

        val hkdfSaltBytes = new Array[Byte](saltLen)
        localRandom.get().nextBytes(hkdfSaltBytes)

        val hkdfParams = hkdfExtractParametersFor(
            argon2Prk.passwordBasedPrk,
            SensitiveBytes(hkdfSaltBytes),
            NamedKeyType.HMACProfile.name
        )

        val prkGenerator = new HKDFBytesGenerator(new SHA512Digest())
        prkGenerator.init(hkdfParams)
        val prkBytes = new Array[Byte](prkLen)
        prkGenerator.generateBytes(prkBytes, 0, prkBytes.length)

        val hmacKey = DestroyablePasswordBasedKeyProfile(
            new DestroyableHmacKey(prkBytes),
            argon2Prk.argon2Salt.copyOf(),
            SensitiveBytes(hkdfSaltBytes)
        )
        argon2Prk.destroy()

        hmacKey
    }

    def rederiveHmacKey(
        passphrase: SensitiveString,
        argon2Salt: SensitiveBytes,
        hkdfSalt: SensitiveBytes
    ): DestroyablePasswordBasedKeyProfile = {
        val argon2Prk = rederivePasswordBasedArgon2PRK(passphrase, argon2Salt)

        val hkdfParams = hkdfExtractParametersFor(
            argon2Prk.passwordBasedPrk,
            hkdfSalt,
            NamedKeyType.HMACProfile.name
        )

        val prkGenerator = new HKDFBytesGenerator(new SHA512Digest())
        prkGenerator.init(hkdfParams)
        val prkBytes = new Array[Byte](prkLen)
        prkGenerator.generateBytes(prkBytes, 0, prkBytes.length)

        val hmacKey = DestroyablePasswordBasedKeyProfile(
            new DestroyableHmacKey(prkBytes),
            argon2Prk.argon2Salt.copyOf(),
            hkdfSalt
        )
        argon2Prk.destroy()

        hmacKey
    }


    private def hkdfExtractParametersFor(
        argon2Prk: SensitiveBytes,
        hkdfSalt: SensitiveBytes,
        associatedData: String): HKDFParameters =
    {
        new HKDFParameters(
            argon2Prk.bytes,
            hkdfSalt.bytes,
            associatedData.getBytes(StandardCharsets.UTF_8)
        )
    }

    private def hkdfExtractParametersFor(argon2Prk: SensitiveBytes, associatedData: String): HKDFParameters = {
        val saltBytes = new Array[Byte](saltLen)
        localRandom.get().nextBytes(saltBytes)

        hkdfExtractParametersFor(argon2Prk, SensitiveBytes(saltBytes), associatedData)
    }
}
