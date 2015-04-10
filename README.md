# Kinject-x64
Kinject - kernel dll injector, currently available in x86 version, will be updated to x64 soon. Here you may find only driver, the application itself will be published after I finish the x64 version.

Basic structure of the driver:


Find a thread to hijack. 
 
Open the target process. 
 
Open the target thread. 
Attach to target process's address space.
 
Allocate memory in target process's address space. 
 
Copy the DLL name and APC routine into target process's address space. 
Set ApcState.UserApcPending to TRUE to force the target thread to execute the APC routine.
 
Allocate an APC object from nonpaged pool. 
Initialize the APC and insert it to the target thread.//KeInitializeApc,KeInsertQueueApc
 
The target thread executes the APC routine in target process's address space. The APC routine calls LdrLoadDll to load the DLL.
 
Wait for the APC routine to complete.
 
Free the allocated memory.
 
Detach from target process's address space. 
 
Dereference the target process and target thread. 
