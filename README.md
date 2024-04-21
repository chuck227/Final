# Description
This project attempts to detect process injection of known malicious code. It achomplishes this in one of two ways depending on the user's preference:
1. By comparing the hash of newly started threads with known bad hashes
2. By comparing a subset of the binaries in new threads with user defined known bad binaries.
Since this comparison is done after a thread starts, this can be used to detect malware which may have encrypted the actual shellcode on disk before injection to avoid other detections.
Additionally, this supports two modes. The first is to monitor given processes actively for injection. The second is to scan all running processes for existing threads which match these signatures. For best performance, this should be run as an administrator to be able to scan more processes than an unprivileged account may be able to.

# Overview of Methodology
This scanning project works by first opening the target process for debugging. When this occurs, windows will immediately alert the debugger of all running threads. For each running thread we either hash the binaries of thread, or compare the binaries with the provided known bad signatures. If the scanning tool is running in all mode then it will disconnect from the process and continue scanning other services. If the scanning tool is set to target this specific process then it will continue to monitor the process. If a new thread is started then the same comparison is done to the newly started thread as previously described.

# Usage
Final.exe [/b] [ name of process | all ]

|Switch|Description|
|---|---|
|/b|Use this switch to scan for a subset of binaries rather than hashing the threads|
| name of process or all|Either type the name of the process you'd like to actively watch i.e. notepad.exe OR type all to scan all running processes and then exit|