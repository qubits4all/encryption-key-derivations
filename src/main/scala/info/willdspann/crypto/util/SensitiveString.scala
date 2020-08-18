package info.willdspann.crypto.util

import javax.security.auth.Destroyable

case class SensitiveString(chars: Array[Char]) extends Destroyable {
    @volatile private var destroyed = false

    override def destroy(): Unit = {
        SensitiveDataUtils.clearChars(chars)
        destroyed = true
    }

    override def isDestroyed: Boolean = destroyed

    override def toString: String = new String(chars)
}
