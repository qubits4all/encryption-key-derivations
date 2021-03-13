package info.willdspann.crypto

import javax.security.auth.Destroyable

import info.willdspann.crypto.util.SensitiveBytes

case class DestroyableArgon2KeyProfile(passwordBasedPrk: SensitiveBytes, argon2Salt: SensitiveBytes) extends Destroyable {

    override def destroy(): Unit = {
        passwordBasedPrk.destroy()
        argon2Salt.destroy()
    }

    override def isDestroyed: Boolean =
        passwordBasedPrk.isDestroyed && argon2Salt.isDestroyed
}

case class DestroyableHkdfKeyProfile(hkdfPrk: DestroyableKey, hkdfSalt: SensitiveBytes) extends Destroyable {

    override def destroy(): Unit = {
        hkdfPrk.destroy()
        hkdfSalt.destroy()
    }

    override def isDestroyed: Boolean =
        hkdfPrk.isDestroyed && hkdfSalt.isDestroyed
}

case class DestroyablePasswordBasedKeyProfile(
    passwordBasedHkdfPrk: DestroyableKey,
    argon2Salt: SensitiveBytes,
    hkdfSalt: SensitiveBytes
) extends Destroyable {

    override def destroy(): Unit = {
        passwordBasedHkdfPrk.destroy()
        argon2Salt.destroy()
        hkdfSalt.destroy()
    }

    override def isDestroyed: Boolean =
        passwordBasedHkdfPrk.isDestroyed && argon2Salt.isDestroyed && hkdfSalt.isDestroyed
}
