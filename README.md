## Installation Instructions

1. **Download the Project Files:**
   - Clone or download this repository.

2. **Dependencies:**
   - [Apache Commons Math](https://commons.apache.org/proper/commons-math/) - Apache License 2.0
   - [Bouncy Castle](https://www.bouncycastle.org/) - MIT License

Ensure all external libraries are placed in the `lib` directory.

## Compilation and Execution

### Unix/Linux

:: Compilation
`javac -cp "bin:lib/*" -d bin src/encryption/*.java src/hash/*.java src/sageo/*.java src/util/*.java src/fme/*.java`

:: Execution
`java -cp "bin:lib/*" fme.FME`


### Windows

:: Compilation
`javac -cp "bin;lib\\*" -d bin src/encryption/*.java src/hash/*.java src/sageo/*.java src/util/*.java src/fme/*.java`

:: Execution
`java -cp "bin;lib\\*" fme.FME`
