## Direct Syscall Injection
This repository demonstrates Direct Syscall Injection on Windows. It shows how to inject and execute shellcode directly within a target process using system calls via the NT Native API (ntdll.dll). Unlike normal Windows API calls, this technique interacts directly with the kernel.

## How It Works
Load NTDLL: The code dynamically loads ntdll.dll and retrieves the addresses of the system calls using GetProcAddress.
Open Target Process: A handle to the target process is opened using NtOpenProcess.
Allocate Memory: Memory is allocated inside the target process for the shellcode.
Write Shellcode: The shellcode is written into the allocated memory.
Change Protection: The memory protection is changed to allow execution (PAGE_EXECUTE_READ).
Create Remote Thread: A new thread is created in the target process to run the shellcode.
Wait for Completion: The program waits for the thread to finish.
Cleanup: The allocated memory is freed, and handles are closed.

## Code Files
main.c: The main code file demonstrating syscall injection.
inject.asm: Shellcode to be injected into the target process.
syscalls.h: Header file defining function prototypes and syscall numbers.
Requirements
Windows OS (Tested on Windows 10)
Visual Studio or any C compiler that supports Windows API
A target process (for example, Notepad or any process with known PID)

./syscall_inject <Target PID>

## Notes
This technique is for educational purposes and is meant to demonstrate low-level Windows internals.
Direct Syscall Injection bypasses API hooks and can be used in penetration testing or malware research.
Always get proper authorization before testing on any system
.
## License
This project is licensed under the MIT License - see the LICENSE file for details.
