.data

extern NTOPENPROCESS_SSN:DWORD
extern NTALLOC_SSN:DWORD
extern NTWRITE_SSN:DWORD
extern NTPROTECT_SSN:DWORD
extern NTCREATETHREAD_SSN:DWORD
extern NTWAIT_SSN:DWORD
extern NTFREE_SSN:DWORD
extern NTCLOSE_SSN:DWORD

.code 
NtOpenProcess proc
		mov r10,rcx
		mov eax,NTOPENPROCESS_SSN
		syscall
		ret
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10,rcx
		mov eax,NTALLOC_SSN
		syscall
		ret
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10,rcx
		mov eax,NTWRITE_SSN
		syscall
		ret
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
		mov r10,rcx
		mov eax,NTPROTECT_SSN
		syscall 
		ret
NtProtectVirtualMemory endp

NtCreateThreadEx proc
		mov r10,rcx
		mov eax,NTCREATETHREAD_SSN
		syscall
		ret
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10,rcx
		mov eax,NTWAIT_SSN
		syscall
		ret
NtWaitForSingleObject endp

NtFreeVirtualMemory proc
		mov r10,rcx
		mov eax,NTFREE_SSN
		syscall
		ret
NtFreeVirtualMemory endp

NtClose proc
		mov r10,rcx
		mov eax,NTCLOSE_SSN
		syscall
		ret
NtClose endp

end