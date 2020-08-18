package info.willdspann.crypto.util

import javax.security.auth.Destroyable

case class SensitiveBytes(bytes: Array[Byte]) extends Destroyable {
    @volatile private var destroyed = false

    override def destroy(): Unit = {
        SensitiveDataUtils.clearBytes(bytes)
        destroyed = true
    }

    override def isDestroyed: Boolean = destroyed
}
