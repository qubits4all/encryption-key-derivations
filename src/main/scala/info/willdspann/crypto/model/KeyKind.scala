package info.willdspann.crypto.model

sealed abstract class KeyKind(val name: String)

object KeyKind {
    val PseudoRandomKey: KeyKind = new KeyKind("PRK") {}
    val HmacKey: KeyKind = new KeyKind("HMAC") {}
    val SymmetricSecretKey: KeyKind = new KeyKind("Symmetric") {}
    val PublicKey: KeyKind = new KeyKind("Public") {}
    val PrivateKey: KeyKind = new KeyKind("Private") {}
    val SecretSeed: KeyKind = new KeyKind("Secret_Seed") {}
}
