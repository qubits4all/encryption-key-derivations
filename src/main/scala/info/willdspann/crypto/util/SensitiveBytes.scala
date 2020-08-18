package info.willdspann.crypto.util

import java.security.SecureRandom

import javax.annotation.concurrent.ThreadSafe
import javax.security.auth.Destroyable

case class SensitiveBytes(bytes: Array[Byte]) extends Destroyable {
    @volatile private var destroyed = false

    override def destroy(): Unit = {
        SensitiveDataUtils.clearBytes(bytes)
        destroyed = true
    }

    override def isDestroyed: Boolean = destroyed
}

@ThreadSafe
object SensitiveBytes {
    private val localRandom: ThreadLocal[SecureRandom] = ThreadLocal.withInitial(() => new SecureRandom())

    def randomBytes(length: Int): SensitiveBytes = {
        if (length <= 0)
            throw new IllegalArgumentException("Only a positive number of random bytes may be generated.")

        val bytes = new Array[Byte](length)
        localRandom.get().nextBytes(bytes)
        SensitiveBytes(bytes)
    }
}
