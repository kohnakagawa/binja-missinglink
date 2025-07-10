#!/bin/bash

# Set architecture to x86_64
export ARCHFLAGS="-arch x86_64"

# Build C test program
echo "Building C test program..."
cd c_test
# Compile with x86_64 architecture flag and position independent code
clang -arch x86_64 -o main main.c -ldl
clang -arch x86_64 -shared -o libtest_module.dylib libtest_module.c
cd ..

# Build Swift test program
echo "Building Swift test program..."
cd swift_test
# Compile Swift with x86_64 architecture flag
swiftc -O -target x86_64-apple-macosx10.15 -o TestProgramClass TestProgramClass.swift
strip TestProgramClass
swiftc -O -target x86_64-apple-macosx10.15 -o TestProgramStruct TestProgramStruct.swift
strip TestProgramStruct
cd ..

echo "Build complete!"
echo "To run C test program: cd c_test && ./main"
echo "To run Swift test program: cd swift_test && ./TestProgramClass"