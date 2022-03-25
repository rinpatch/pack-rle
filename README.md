# pack-rle

A simple run-length compressor/decompressor written in Kotlin as a uni assignment.

## Building

```sh
gradle jar
```

## Running

```sh
# Compress
java -jar build/libs/pack-rle-1.0-SNAPSHOT.jar -z testfile.txt
# Decompress
java -jar build/libs/pack-rle-1.0-SNAPSHOT.jar -u testfile.txt.rle
```

## Testing

A [fuzz target](src/main/kotlin/FuzzTarget.kt) for [jazzer](https://github.com/CodeIntelligenceTesting/jazzer) is implemented.

If using Docker, it can be run as follows:
```sh
mkdir fuzzing
cp build/libs/pack-rle-1.0-SNAPSHOT.jar fuzzing
docker run -v $PWD/fuzzing:/fuzzing cifuzz/jazzer --cp=pack-rle-1.0-SNAPSHOT.jar --target_class=FuzzTarget
```