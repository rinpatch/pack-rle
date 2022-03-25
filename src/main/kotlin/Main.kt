import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import java.io.File
import java.io.OutputStream
import java.lang.IllegalArgumentException
import java.security.DigestInputStream
import java.security.DigestOutputStream
import java.security.MessageDigest

fun main(args: Array<String>) {
    val parser = ArgParser("pack-rle", prefixStyle = ArgParser.OptionPrefixStyle.JVM)
    val output by parser.option(ArgType.String, shortName = "o", fullName = "out", description = "Output file name")
    val compress by parser.option(
        ArgType.Boolean,
        shortName = "z",
        description = "Compress the input. Cannot be used in conjunction with -u"
    )
    val uncompress by parser.option(
        ArgType.Boolean,
        shortName = "u",
        description = "Uncompress the input. Cannot be used in conjunction with -z"
    )
    val doNotDeleteOnDigestMismatch by parser.option(
        ArgType.Boolean,
        description = "Do not delete the file on decompression, in case the digest does not match. Mostly useful for testing."
    ).default(false)
    val force by parser.option(
        ArgType.Boolean,
        shortName = "f",
        description = "Overwrite the output file if it exists."
    ).default(false)
    val input by parser.argument(ArgType.String, description = "Input file name")
    parser.parse(args)
    when {
        compress ?: false && uncompress ?: false -> throw IllegalArgumentException("Can't use both -z and -u at the same time")
        compress ?: false -> compressFile(input, output, force)
        uncompress ?: false -> uncompressFile(input, output, force, !doNotDeleteOnDigestMismatch)
        compress == null && uncompress == null -> throw IllegalArgumentException("One of -z or -u should be specified")
    }
}

// .rle File format
//  Signature: 3 bytes
val SIGNATURE = "RLE".toByteArray(Charsets.US_ASCII)
// Packets:
// Each packet starts with a length byte. The first bit from the left is used for packet type (0 - run, 1 - raw)
// The other 7 bits signify packet length (in bytes), meaning packets can be at most 127 bytes in length.
// A packet with 0 length signifies end of data and start of digest.
const val PACKET_SIZE_CAP = 127
const val RAW_FLAG = 128
// Digest: A SHA-256 checksum of the input file. Used to verify integrity after decompressing.
const val DIGEST_BYTE_SIZE = 32

fun writeRawPacket(buffer: List<Int>, outputStream: OutputStream) {
    if (buffer.size > PACKET_SIZE_CAP) throw IllegalStateException("writeRawPacket called with oversized buffer. size = ${buffer.size}")
    if (buffer.size == 0) throw IllegalStateException("writeRawPacket called with buffer.size=0, reserved for EOF")
    outputStream.write(buffer.size.or(RAW_FLAG))
    buffer.forEach { outputStream.write(it) }
}

fun writeRunPacket(byte: Int, len: Int, outputStream: OutputStream) {
    if (len > PACKET_SIZE_CAP) throw IllegalStateException("writeRunPacket called with oversized buffer. len = $len")
    if (len == 0) throw IllegalStateException("writeRunPacket called with len=0, reserved for EOF")
    outputStream.write(len)
    outputStream.write(byte)
}

fun getFiles(inputName: String, outputName: String, force: Boolean): Pair<File, File> {
    val outputFile = File(outputName)
    val inputFile = File(inputName)
    if (!inputFile.exists()) throw IllegalArgumentException("Input file does not exist")
    if (outputFile.exists()) {
        if (force) outputFile.delete()
        else throw IllegalArgumentException("Output file exists. Not overwriting since -f is not specified.")
    }
    return inputFile to outputFile
}

fun safeUseFile(file: File, outputStream: OutputStream, user: (OutputStream) -> Unit) =
    try {
        outputStream.use {
            user(outputStream)
        }
    } catch (e: Exception) {
        file.delete()
        throw e
    }


fun compressFile(inputName: String, outputName: String?, force: Boolean) {
    val (inputFile, outputFile) = getFiles(inputName, outputName ?: "$inputName.rle", force)

    safeUseFile(outputFile, outputFile.outputStream().buffered()) { writer ->
        writer.write(SIGNATURE)
        val md = MessageDigest.getInstance("SHA-256")
        val inputStream = DigestInputStream(inputFile.inputStream().buffered(), md)
        inputStream.use { reader ->
            var lastByte = reader.read()
            val rawBuf = mutableListOf<Int>()
            if (lastByte != -1) rawBuf.add(lastByte)
            var byte = reader.read()
            var rawMode = true
            var runLength = 1
            while (byte != -1) {
                if (rawMode) rawBuf.add(byte)
                if (lastByte == byte) {
                    runLength += 1
                    if (rawMode && runLength == 2) {
                        if (rawBuf.size != runLength) writeRawPacket(rawBuf.subList(0, rawBuf.lastIndex - 1), writer)
                        rawBuf.clear()
                        rawMode = false
                    }
                } else if (!rawMode) {
                    writeRunPacket(lastByte, runLength, writer)
                    runLength = 1
                    rawMode = true
                    rawBuf.add(byte)
                } else {
                    runLength = 1
                }

                lastByte = byte

                if (rawBuf.size == PACKET_SIZE_CAP) {
                    writeRawPacket(rawBuf, writer)
                    runLength = 0
                    lastByte = -1
                    rawBuf.clear()
                }
                if (runLength == PACKET_SIZE_CAP) {
                    writeRunPacket(byte, runLength, writer)
                    runLength = 0
                    lastByte = -1
                    rawMode = true
                }

                byte = reader.read()
            }
            if (rawMode && rawBuf.size > 0) {
                writeRawPacket(rawBuf, writer)
            } else if (!rawMode && runLength > 0) {
                writeRunPacket(lastByte, runLength, writer)
            }

            writer.write(0)
            writer.write(md.digest())
        }
    }
}

enum class PacketType {
    RAW,
    RUN,
    DIGEST
}

fun parsePacket(packet: Int): Pair<PacketType, Int> =
    when {
        packet == 0 -> PacketType.DIGEST to DIGEST_BYTE_SIZE
        packet.and(RAW_FLAG) != 0 -> PacketType.RAW to packet.xor(RAW_FLAG)
        else -> PacketType.RUN to packet
    }

fun uncompressFile(inputName: String, outputName: String?, force: Boolean, deleteOnDigestMismatch: Boolean) {
    val outputName = outputName ?: if (inputName.endsWith(".rle")) {
        inputName.removeSuffix(".rle")
    } else throw IllegalArgumentException("Can't infer output filename. Please specify it explicitly")
    val (inputFile, outputFile) = getFiles(inputName, outputName, force)
    inputFile.inputStream().buffered().use { reader ->
        if (!reader.readNBytes(SIGNATURE.size)
                .contentEquals(SIGNATURE)
        ) throw IllegalStateException("Not an RLE compressed file.")
        val md = MessageDigest.getInstance("SHA-256")
        val outputStream = DigestOutputStream(outputFile.outputStream(), md)
        var specifiedDigest: ByteArray? = null
        safeUseFile(outputFile, outputStream.buffered()) { writer ->
            var packet = reader.read()
            while (packet != -1) {
                val (type, length) = parsePacket(packet)
                when (type) {
                    PacketType.RAW -> writer.write(reader.readNBytes(length))
                    PacketType.RUN -> {
                        val byte = reader.read()
                        repeat(length) { writer.write(byte) }
                    }
                    else -> {
                        specifiedDigest = reader.readNBytes(length)
                        if (reader.read() != -1) throw IllegalStateException("File continues after digest.")
                    }
                }
                packet = reader.read()
            }
        }
        if (specifiedDigest == null) {
            outputFile.delete()
            throw IllegalStateException("File does not have a digest segment.")
        } else {
            if (!specifiedDigest.contentEquals(md.digest())) {
                if (deleteOnDigestMismatch) outputFile.delete()
                throw IllegalStateException("Digest of the decompressed file does not match the expectation.")
            }
        }
    }
}