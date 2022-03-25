import java.io.File
import kotlin.io.path.createTempFile
import kotlin.io.path.writeBytes

object FuzzTarget {
    @JvmStatic
    fun fuzzerTestOneInput(input: ByteArray) {
        val inputFile = createTempFile()
        val inputFileName = inputFile.toAbsolutePath().toString()
        val compressedFileName = inputFileName + ".rle"
        val reassembledFileName = inputFileName + ".reassembled"
        inputFile.writeBytes(input)
        compressFile(inputFileName, compressedFileName, false)
            uncompressFile(
                compressedFileName,
                reassembledFileName,
                false,
                false
            )
        if (!input.contentEquals(File(reassembledFileName).readBytes())) {
            throw IllegalStateException("Reassembled file does not match original")
        }
    }
}