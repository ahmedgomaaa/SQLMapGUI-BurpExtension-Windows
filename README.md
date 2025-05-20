# SQLMap GUI Extension for Burp Suite

## Overview
This is a modified version of the SQLMap GUI extension for Burp Suite, adapted to work on Windows systems. The extension provides a convenient interface to run SQLMap directly from Burp Suite, eliminating the need for manual request file handling and command-line operations.

## Original Source
This extension is based on the work by Yousef Alotaibi, as described in his Medium article:
[Burp Suite Integration with SQLmap](https://medium.com/@YousefAlotaibi/burp-suite-integration-with-sqlmap-8ee7c65e2a1e)

The original extension was designed for Linux environments, and this version has been modified to work properly on Windows systems.

## Modifications
The following modifications have been made to the original script:

1. **Windows Path Compatibility**: Changed hardcoded Linux paths to work on Windows
2. **SQLMap Path Configuration**: Updated to use a configurable SQLMap path
3. **File Handling**: Improved file saving and reading for Windows compatibility
4. **Jython Compatibility**: Removed Python-specific code that doesn't work in Jython
5. **Error Handling**: Added robust error handling and logging
6. **Temporary File Storage**: Uses Java's temp directory for reliable file storage

## Setup Instructions

### Prerequisites
1. Burp Suite Professional or Community Edition
2. Jython standalone JAR configured in Burp Suite
3. SQLMap installed on your system

### Installation

1. **Configure Jython in Burp Suite**:
   - Go to Burp Suite → Settings → Extensions → Python Environment
   - Set the location of your Jython standalone JAR file

2. **Edit SQLMap Path**:
   - Open the `SQLmapGui.py` file in a text editor
   - Locate the line containing `sqlmap_path = "F:\\sqlmap_last\\sqlmap.py"`
   - Change this path to match your SQLMap installation location
   - Save the file

3. **Load the Extension**:
   - In Burp Suite, go to Extensions → Add
   - Select Extension Type: Python
   - Select the modified `SQLmapGui.py` file
   - The extension should load and a new "SQLMap GUI" tab will appear

## Usage

1. **Sending Requests to SQLMap**:
   - Intercept a request in Burp Suite or select one from the Proxy history
   - Right-click on the request and select "Send to SQLMap"
   - The request will appear in the SQLMap GUI tab

2. **Configuring SQLMap Options**:
   - In the SQLMap GUI tab, select the desired options
   - Common options like risk, level, and techniques are available as checkboxes
   - Additional parameters can be specified for selected options

3. **Running SQLMap**:
   - Select a saved request from the list
   - Click the "Run SQLMap" button
   - SQLMap output will be displayed in the right panel with color coding
   - Green text indicates vulnerability findings
   - Red text indicates errors or critical messages

4. **Stopping SQLMap**:
   - Click the "Stop" button to terminate a running SQLMap process

## Troubleshooting

- **Extension Doesn't Load**: Ensure Jython is properly configured in Burp Suite
- **SQLMap Not Found**: Verify the SQLMap path in the script is correct
- **Request Files Not Saved**: Check if the extension has write permissions to the temp directory
- **SQLMap Process Errors**: Ensure SQLMap is properly installed and can be run from command line

## License
This extension is provided for educational and ethical security testing purposes only. Unauthorized testing against systems without explicit permission is illegal.
