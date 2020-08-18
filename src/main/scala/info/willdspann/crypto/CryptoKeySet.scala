package info.willdspann.crypto

import javax.security.auth.Destroyable

case class CryptoKeySet(
    hmacKey: DestroyableKey,
    profileEncryptionKey: DestroyableKey,
    protectedProfileEncryptionKey: DestroyableKey
) extends Destroyable {

    override def destroy(): Unit = {
        hmacKey.destroy()
        profileEncryptionKey.destroy()
        protectedProfileEncryptionKey.destroy()
    }

    override def isDestroyed: Boolean = {
        hmacKey.isDestroyed && profileEncryptionKey.isDestroyed && protectedProfileEncryptionKey.isDestroyed
    }
}
