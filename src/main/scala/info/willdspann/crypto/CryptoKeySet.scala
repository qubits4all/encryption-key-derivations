package info.willdspann.crypto

import javax.security.auth.Destroyable

import info.willdspann.crypto.util.SensitiveBytes

case class CryptoKeySet(
    hmacKey: DestroyableKey,
    profileEncryptionKey: DestroyableKey,
    protectedProfileEncryptionKey: DestroyableKey,
    hkdfSalt: SensitiveBytes,
    argon2Salt: Option[SensitiveBytes]
) extends Destroyable {

    override def destroy(): Unit = {
        hmacKey.destroy()
        profileEncryptionKey.destroy()
        protectedProfileEncryptionKey.destroy()
        hkdfSalt.destroy()
        argon2Salt.foreach(_.destroy())
    }

    override def isDestroyed: Boolean = {
        hmacKey.isDestroyed && profileEncryptionKey.isDestroyed && protectedProfileEncryptionKey.isDestroyed &&
            hkdfSalt.isDestroyed && argon2Salt.forall(_.isDestroyed)
    }
}
