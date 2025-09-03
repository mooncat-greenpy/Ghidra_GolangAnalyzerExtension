# GolangAnalyzerExtension
The GolangAnalyzerExtension facilitates the analysis of Golang binaries using Ghidra.
It supports multiple Go versions with automated callmap data updates.

## Features
This Ghidra plugin provides the following functionality for analyzing Golang binaries:

- Identification of the Golang version
- Renaming of functions
- Correction of function arguments
- Documentation of source file names and line numbers in comments
- Integration of custom data types into the Data Type Manager
- Capability to search for strings within the binary
- **Automated callmap data updates** to support latest Go versions

## Callmap Data System

### External Callmap Repository
The Go function call mapping data is stored in a separate repository:  
**https://github.com/askme765cs/golang-callmaps**

This repository contains:
- Automated callmap generation for various Go versions
- Versioned releases tagged with Go version numbers (e.g., `go1.24.6`)
- A `latest` tag that always points to the most recent Go version
- Comprehensive function call data for improved binary analysis

### Supported Go Versions
The extension dynamically supports Go versions based on the available callmap data. Check the [latest release](https://github.com/askme765cs/golang-callmaps/releases/latest) for currently supported Go versions.

## Usage
1. Download the latest release
2. Launch Ghidra
3. Go to `File -> Install Extensions... -> Add extension -> Select zip file`
4. Enable the `GolangAnalyzerExtension` by checking its checkbox
5. Restart Ghidra to apply changes
6. Begin analyzing your Golang binary
