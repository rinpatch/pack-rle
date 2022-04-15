import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import kotlin.test.*

class Tests {
    private val overheadSize = SIGNATURE.size + DIGEST_BYTE_SIZE

    private fun getCompressResult(dir: Path, data: ByteArray): ByteArray {
       val input = File.createTempFile("test", null, dir.toFile())
        input.writeBytes(data)
       val outputName = input.path + ".rle"
       compressFile(input.path, outputName, true)
       return File(outputName).readBytes()
    }
    private fun assertSameContentAfterCycling(dir: Path, data: ByteArray) {
        val input = File.createTempFile("test", null, dir.toFile())
        input.writeBytes(data)
        val compressedName = input.path + ".rle"
        compressFile(input.path, compressedName, true)

        val output = File.createTempFile("test", null, dir.toFile())
        uncompressFile(compressedName, output.path, force = true, deleteOnDigestMismatch = true)
        println(output.readBytes())
        assertContentEquals(data, output.readBytes())
    }

    @Test
    fun `Compresses repeating bytes into a run`(@TempDir dir: Path) {
        assertTrue {
            val result = getCompressResult(dir, ByteArray(100))
            (result.size - overheadSize) < 100
        }
    }
    @Test
    fun `Does not bloat up the file size if the content is not compressable`(@TempDir dir: Path) {
       assertTrue {
           val input = ByteArray(100)
           for (i in 4..input.lastIndex) {
               input[i] = (i % 2).toByte()
           }
           val result = getCompressResult(dir, input)
           (result.size - overheadSize) < input.size * 2
       }
    }

    @Test
    fun `Correctly splits the run into multiple packets if above max packet size`(@TempDir dir: Path) {
        assertSameContentAfterCycling(dir, ByteArray(PACKET_SIZE_CAP + 1))
    }

    @Test
    fun `Correctly splits the raw segment into multiple packets if above max packet size`(@TempDir dir: Path) {
        val input = ByteArray(PACKET_SIZE_CAP + 1)
        for (i in input.indices) {
            input[i] = (i % 2).toByte()
        }
        assertSameContentAfterCycling(dir, input)
    }
}