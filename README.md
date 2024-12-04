# Process Dumper

ProcessDumper is a tool designed to dump the memory of a target process (e.g. the unpacked files from a game). It leverages a custom driver to perform process and memory operations, offering flexibility for developers and security researchers. The project is equipped with a GitHub Actions workflow for streamlined builds.

## Features

- Identify and monitor target processes by name.
- Retrieve and parse process memory, including PE headers and sections.
- Save memory dumps to a file with customizable naming.
- Lightweight and efficient with built-in error handling.

## Prerequisites

- **Windows Operating System**: The tool is Windows-specific.
- **Custom Driver**: A driver is required for process interaction. Ensure the driver is properly configured.
- **Visual Studio or Similar IDE**: For local compilation and debugging.

## Usefull links

* https://github.com/justvmexit/dumpr
* https://github.com/EquiFox/KsDumper
* https://github.com/mastercodeon314/KsDumper-11
* https://github.com/skadro-official/PE-Dump-Fixer
* https://www.unknowncheats.me/forum/call-of-duty-modern-warfare-iii/618537-loading-dump-ida-takes-lifetime.html
* https://github.com/Nuxar1/DecryptionDumper
* https://github.com/lauralex/kdprocdumper
