# GolangAnalyzerExtension
The GolangAnalyzerExtension facilitates the analysis of Golang binaries using Ghidra.
It supports go1.6 through go1.25.

## Features
This Ghidra plugin provides the following functionality for analyzing Golang binaries:

- Identification of the Golang version
- Renaming of functions
- Correction of function arguments
- Documentation of source file names and line numbers in comments
- Integration of custom data types into the Data Type Manager
- Capability to search for strings within the binary

Refer to the images below for a visual demonstration.

<img src="img/demo.png">

<img src="img/demo.gif">

## Usage
1. Download the latest release
2. Launch Ghidra
3. Go to `File -> Install Extensions... -> Add extension -> Select zip file`
4. Enable the `GolangAnalyzerExtension` by checking its checkbox
5. Restart Ghidra to apply changes
6. Begin analyzing your Golang binary
