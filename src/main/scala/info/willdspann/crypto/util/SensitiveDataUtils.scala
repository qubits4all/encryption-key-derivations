package info.willdspann.crypto.util

import java.util

object SensitiveDataUtils {

    def clearChars(sensitive: Array[Char]): Array[Char] = {
        util.Arrays.fill(sensitive, 0, sensitive.length, '\u0000')
        sensitive
    }

    def clearBytes(sensitive: Array[Byte]): Array[Byte] = {
        util.Arrays.fill(sensitive, 0, sensitive.length, 0.toByte)
        sensitive
    }
}
