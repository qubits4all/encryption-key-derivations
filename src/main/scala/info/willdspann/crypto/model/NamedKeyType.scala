package info.willdspann.crypto.model

sealed abstract class NamedKeyType(val name: String, val kind: KeyKind)

object NamedKeyType {
    /** A uniformly-distributed PRK derived from a passphrase (i.e., using Argon2 followed by HKDF Extract). */
    val PasswordBasedEncryptionPRK: NamedKeyType = new NamedKeyType("PBE_PRK", KeyKind.PseudoRandomKey) {}
    /** A uniformly-distributed PRK derived from a biometrics-based authentication and random salt
     *  (i.e., via WebAuthn API & PRF extension) */
    val BiometricsBasedEncryptionPRK: NamedKeyType = new NamedKeyType("Biometrics_PRK", KeyKind.PseudoRandomKey) {}
    /** HMAC key used to ensure the integrity and authenticity of an encrypted offline profile. */
    val HMACProfile: NamedKeyType = new NamedKeyType("Profile_HMAC", KeyKind.HmacKey) {}
    /** Pseudorandom base PRK generated using a cryptographically-secure PRNG (CSPRNG). All data encryption keys, IVs
     *  and any additional HMAC keys should be generated from this base PRK (i.e., using HKDF Expand). */
    val RandomBasePRK: NamedKeyType = new NamedKeyType("Random_PRK", KeyKind.PseudoRandomKey) {}

    val ProfileAESEncryption: NamedKeyType = new NamedKeyType("Profile_AES", KeyKind.SymmetricSecretKey) {}
    val ProtectedProfileAESEncryption: NamedKeyType = new NamedKeyType("ProtectedProfile_AES", KeyKind.SymmetricSecretKey) {}
    val TOTPSecretSeed: NamedKeyType = new NamedKeyType("SecretSeed_TOTP", KeyKind.SecretSeed) {}
    val SigningKey: NamedKeyType = new NamedKeyType("SigningKey_ECDSA", KeyKind.PrivateKey) {}
    val SignatureVerificationKey: NamedKeyType = new NamedKeyType("VerificationKey_ECDSA", KeyKind.PublicKey) {}
}
