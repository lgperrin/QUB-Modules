# Malware Analysis Tools and Techniques

## Basic Static Analysis

| Tool               | Functionality                                                                                                 |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| PE Viewer          | - `IMAGE_NT_HEADERS > IMAGE_FILE_HEADERS` to see timestamps of the program                                    |
|                    | - `IMAGE_SECTION_HEADER` to see if the program was packed                                                     |
|                    | - `SECTION .rdata > IMPORT Address Table` to see malware’s imports and strings                                |
| PEiD               | - To see if the program was packed                                                                            |
| Dependency Walker  | - `KERNELL.DDL` to see dynamically functions imported by malware                                              |
| Strings.exe        | - To see any host-based or network-based indicators                                                           |

## Basic Dynamic Analysis

| Tool                         | Functionality                                                                                               |
|------------------------------|-------------------------------------------------------------------------------------------------------------|
| ApateDNS                     | - For spoofing DNS requests on the local machine                                                            |
| Process Monitor (Procmon.exe)| - `ProcessName is Lab06-02.exe` Check for the program Lab06-02.exe                                         |
| Process Monitor (Procmon.exe)| - `Operation is RegSetValue` to see if the program sets any registry values                                 |
| Process Monitor (Procmon.exe)| - `Operation is WriteFile` to see if the program writes any file                                            |
| Process Explorer (procep.exe)| - `View > Lower Pane View > DLLs or Handles` to check if the malware has loaded certain DLLs and has handles |
| Wireshark                    | - To monitor HTTP or TCP connections                                                                         |
