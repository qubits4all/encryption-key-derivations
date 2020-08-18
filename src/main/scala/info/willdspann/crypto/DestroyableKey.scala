package info.willdspann.crypto

import java.security.Key

import info.willdspann.crypto.util.SensitiveBytes
import javax.security.auth.Destroyable

abstract class DestroyableKey(keyBytes: Array[Byte]) extends Key with Destroyable {
    private val keyData: SensitiveBytes = SensitiveBytes(keyBytes)

    override def getEncoded: Array[Byte] = keyData.bytes

    override def destroy(): Unit = keyData.destroy()
    override def isDestroyed: Boolean = keyData.isDestroyed
}

class DestroyableAesKey(keyBytes: Array[Byte]) extends DestroyableKey(keyBytes) {
    override def getAlgorithm: String = "AES"
    override def getFormat: String = null
}
