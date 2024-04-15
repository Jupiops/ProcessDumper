# Process Dumper

This is a simple tool to dump the unpacked files from the game

## Usefull links

* https://github.com/justvmexit/dumpr
* https://github.com/EquiFox/KsDumper
* https://github.com/mastercodeon314/KsDumper-11
* https://github.com/skadro-official/PE-Dump-Fixer
* https://www.unknowncheats.me/forum/call-of-duty-modern-warfare-iii/618537-loading-dump-ida-takes-lifetime.html
* https://github.com/Nuxar1/DecryptionDumper
* https://github.com/lauralex/kdprocdumper


```
I have a windows cpp console application that has a socket connection to a windows kernel mode driver and can use this driver among other things to read memory from other running programs by instructing the driver to copy the memory of the other program to its own memory areas.
I want to use this functionality to make a complete dump of a running program. So far I have the following code.
Can you help me change the code to instead of copying each section with one single read the program reads each section in 4 MB chunks and if it encounters a  STATUS_PARTIAL_COPY it skips over the area until it has either attempted to read the whole section or can read the memory again without errors. The RESULT object which get’s returned by the Driver::ReadMemory contains in its value parameter the size of successfully read memory when a STATUS_PARTIAL_COPY occurs. After each section I would like to print out how much memory needed to be skipped and therefore could not be read successfully.
```