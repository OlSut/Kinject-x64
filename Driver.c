#include <ntifs.h>
#include <ntddk.h>

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION,*PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO,*PSYSTEM_PROCESS_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     USHORT LoadCount;
     USHORT TlsIndex;

     union
     {
          LIST_ENTRY HashLinks;

          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };

     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };

     struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
}LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER
{
     USHORT e_magic;
     USHORT e_cblp;
     USHORT e_cp;
     USHORT e_crlc;
     USHORT e_cparhdr;
     USHORT e_minalloc;
     USHORT e_maxalloc;
     USHORT e_ss;
     USHORT e_sp;
     USHORT e_csum;
     USHORT e_ip;
     USHORT e_cs;
     USHORT e_lfarlc;
     USHORT e_ovno;
     USHORT e_res[4];
     USHORT e_oemid;
     USHORT e_oeminfo;
     USHORT e_res2[10];
     LONG e_lfanew;
}IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
     ULONG VirtualAddress;
     ULONG Size;
}IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER
{
     USHORT Machine;
     USHORT NumberOfSections;
     ULONG TimeDateStamp;
     ULONG PointerToSymbolTable;
     ULONG NumberOfSymbols;
     USHORT SizeOfOptionalHeader;
     USHORT Characteristics;
}IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER
{
     USHORT Magic;
     UCHAR MajorLinkerVersion;
     UCHAR MinorLinkerVersion;
     ULONG SizeOfCode;
     ULONG SizeOfInitializedData;
     ULONG SizeOfUninitializedData;
     ULONG AddressOfEntryPoint;
     ULONG BaseOfCode;
     ULONG BaseOfData;
     ULONG ImageBase;
     ULONG SectionAlignment;
     ULONG FileAlignment;
     USHORT MajorOperatingSystemVersion;
     USHORT MinorOperatingSystemVersion;
     USHORT MajorImageVersion;
     USHORT MinorImageVersion;
     USHORT MajorSubsystemVersion;
     USHORT MinorSubsystemVersion;
     ULONG Win32VersionValue;
     ULONG SizeOfImage;
     ULONG SizeOfHeaders;
     ULONG CheckSum;
     USHORT Subsystem;
     USHORT DllCharacteristics;
     ULONG SizeOfStackReserve;
     ULONG SizeOfStackCommit;
     ULONG SizeOfHeapReserve;
     ULONG SizeOfHeapCommit;
     ULONG LoaderFlags;
     ULONG NumberOfRvaAndSizes;
     IMAGE_DATA_DIRECTORY DataDirectory[16];
}IMAGE_OPTIONAL_HEADER,*PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
     ULONG Signature;
     IMAGE_FILE_HEADER FileHeader;
     IMAGE_OPTIONAL_HEADER OptionalHeader;
}IMAGE_NT_HEADERS,*PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;
    ULONG   AddressOfNames;
    ULONG   AddressOfNameOrdinals;
}IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass,PVOID Buffer,ULONG Length,PULONG ReturnLength);
extern "C" LPSTR PsGetProcessImageFileName(PEPROCESS Process);

typedef NTSTATUS (*PLDR_LOAD_DLL)(PWSTR,PULONG,PUNICODE_STRING,PVOID*);

typedef struct _INJECT_INFO
{
	HANDLE ProcessId;
	wchar_t DllName[1024];
}INJECT_INFO,*PINJECT_INFO;

typedef struct _KINJECT
{
	UNICODE_STRING DllName;
	wchar_t Buffer[1024];
	PLDR_LOAD_DLL LdrLoadDll;
	PVOID DllBase;
	ULONG Executed;
}KINJECT,*PKINJECT;

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
}KAPC_ENVIRONMENT,*PKAPC_ENVIRONMENT;

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
    );

typedef VOID KKERNEL_ROUTINE(
    PRKAPC Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2
    );

typedef KKERNEL_ROUTINE (NTAPI *PKKERNEL_ROUTINE);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
    PRKAPC Apc
    );

extern "C" void KeInitializeApc(
    PRKAPC Apc,
    PRKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ProcessorMode,
    PVOID NormalContext
    );

extern "C" BOOLEAN KeInsertQueueApc(
    PRKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
    );

UNICODE_STRING DeviceName=RTL_CONSTANT_STRING(L"\\Device\\KeInject"),SymbolicLink=RTL_CONSTANT_STRING(L"\\DosDevices\\KeInject");

ULONG ApcStateOffset; // Offset to the ApcState structure
PLDR_LOAD_DLL LdrLoadDll; // LdrLoadDll address

void Unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("DLL injection driver unloaded.");

	IoDeleteSymbolicLink(&SymbolicLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

void NTAPI KernelRoutine(PKAPC apc,PKNORMAL_ROUTINE* NormalRoutine,PVOID* NormalContext,PVOID* SystemArgument1,PVOID* SystemArgument2)
{
	ExFreePool(apc);
}

void NTAPI InjectDllApc(PVOID NormalContext,PVOID SystemArgument1,PVOID SystemArgument2)
{
	PKINJECT inject=(PKINJECT)NormalContext;

	inject->LdrLoadDll(NULL,NULL,&inject->DllName,&inject->DllBase);
	inject->Executed=TRUE;
}

BOOLEAN InjectDll(PINJECT_INFO InjectInfo)
{
	PEPROCESS Process;
	PETHREAD Thread;

	PKINJECT mem;
	ULONG size;

	PKAPC_STATE ApcState;
	PKAPC apc;

	PVOID buffer;
	PSYSTEM_PROCESS_INFO pSpi;

	LARGE_INTEGER delay;

	buffer=ExAllocatePool(NonPagedPool,1024*1024); // Allocate memory for the system information

	if(!buffer)
	{
		DbgPrint("Error: Unable to allocate memory for the process thread list.");
		return FALSE;
	}

	// Get the process thread list

	if(!NT_SUCCESS(ZwQuerySystemInformation(5,buffer,1024*1024,NULL)))
	{
		DbgPrint("Error: Unable to query process thread list.");
		
		ExFreePool(buffer);
		return FALSE;
	}

	pSpi=(PSYSTEM_PROCESS_INFO)buffer;

	// Find a target thread

	while(pSpi->NextEntryOffset)
	{
		if(pSpi->UniqueProcessId==InjectInfo->ProcessId)
		{
			DbgPrint("Target thread found. TID: %d",pSpi->Threads[0].ClientId.UniqueThread);
			break;
		}

		pSpi=(PSYSTEM_PROCESS_INFO)((PUCHAR)pSpi+pSpi->NextEntryOffset);
	}

	// Reference the target process

	if(!NT_SUCCESS(PsLookupProcessByProcessId(InjectInfo->ProcessId,&Process)))
	{
		DbgPrint("Error: Unable to reference the target process.");
		
		ExFreePool(buffer);
		return FALSE;
	}

	DbgPrint("Process name: %s",PsGetProcessImageFileName(Process));
	DbgPrint("EPROCESS address: %#x",Process);

	// Reference the target thread

	if(!NT_SUCCESS(PsLookupThreadByThreadId(pSpi->Threads[0].ClientId.UniqueThread,&Thread)))
	{
		DbgPrint("Error: Unable to reference the target thread.");
		ObDereferenceObject(Process); // Dereference the target process

		ExFreePool(buffer); // Free the allocated memory
		return FALSE;
	}

	DbgPrint("ETHREAD address: %#x",Thread);

	ExFreePool(buffer); // Free the allocated memory
	KeAttachProcess(Process); // Attach to target process's address space

	mem=NULL;
	size=4096;

	// Allocate memory in the target process

	if(!NT_SUCCESS(ZwAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&mem,0,&size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE)))
	{
	    DbgPrint("Error: Unable to allocate memory in the target process.");
		KeDetachProcess(); // Detach from target process's address space

		ObDereferenceObject(Process); // Dereference the target process
		ObDereferenceObject(Thread); // Dereference the target thread

		return FALSE;
	}

	DbgPrint("Memory allocated at %#x",mem);

	mem->LdrLoadDll=LdrLoadDll; // Write the address of LdrLoadDll to target process
	wcscpy(mem->Buffer,InjectInfo->DllName); // Write the DLL name to target process

	RtlInitUnicodeString(&mem->DllName,mem->Buffer); // Initialize the UNICODE_STRING structure
	ApcState=(PKAPC_STATE)((PUCHAR)Thread+ApcStateOffset); // Calculate the address of the ApcState structure

	ApcState->UserApcPending=TRUE; // Force the target thread to execute APC

	memcpy((PKINJECT)(mem+1),InjectDllApc,(ULONG)KernelRoutine-(ULONG)InjectDllApc); // Copy the APC code to target process
	DbgPrint("APC code address: %#x",(PKINJECT)(mem+1));

	apc=(PKAPC)ExAllocatePool(NonPagedPool,sizeof(KAPC)); // Allocate the APC object

	if(!apc)
	{
		DbgPrint("Error: Unable to allocate the APC object.");
		size=0;

		ZwFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&mem,&size,MEM_RELEASE);  // Free the allocated memory
		KeDetachProcess(); // Detach from target process's address space

		ObDereferenceObject(Process); // Dereference the target process
		ObDereferenceObject(Thread); // Dereference the target thread

		return FALSE;
	}

	KeInitializeApc(apc,Thread,OriginalApcEnvironment,KernelRoutine,NULL,(PKNORMAL_ROUTINE)((PKINJECT)mem+1),UserMode,mem); // Initialize the APC
	DbgPrint("Inserting APC to target thread");

	// Insert the APC to the target thread

	if(!KeInsertQueueApc(apc,NULL,NULL,IO_NO_INCREMENT))
	{
		DbgPrint("Error: Unable to insert APC to target thread.");
		size=0;
		
		ZwFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&mem,&size,MEM_RELEASE); // Free the allocated memory
		KeDetachProcess(); // Detach from target process's address space

		ObDereferenceObject(Process); // Dereference the target process
		ObDereferenceObject(Thread); // Dereference the target thread

		ExFreePool(apc); // Free the APC object
		return FALSE;
	}

	delay.QuadPart=-100*10000;

	while(!mem->Executed)
	{
		KeDelayExecutionThread(KernelMode,FALSE,&delay); // Wait for the injection to complete
	}

	if(!mem->DllBase)
	{
		DbgPrint("Error: Unable to inject DLL into target process.");
		size=0;

		ZwFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&mem,&size,MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(Process);
		ObDereferenceObject(Thread);
		
		return FALSE;
	}

	DbgPrint("DLL injected at %#x",mem->DllBase);
	size=0;

	ZwFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&mem,&size,MEM_RELEASE); // Free the allocated memory
	KeDetachProcess(); // Detach from target process's address space

	ObDereferenceObject(Process); // Dereference the target process
	ObDereferenceObject(Thread);  // Dereference the target thread

	return TRUE;
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject,PIRP irp)
{
	PIO_STACK_LOCATION io;
	PINJECT_INFO InjectInfo;

	NTSTATUS status;

	io=IoGetCurrentIrpStackLocation(irp);
	irp->IoStatus.Information=0;

	switch(io->MajorFunction)
	{
	    case IRP_MJ_CREATE:
			status=STATUS_SUCCESS;
			break;
		case IRP_MJ_CLOSE:
			status=STATUS_SUCCESS;
			break;
		case IRP_MJ_READ:
			status=STATUS_SUCCESS;
			break;
		case IRP_MJ_WRITE:

			InjectInfo=(PINJECT_INFO)MmGetSystemAddressForMdlSafe(irp->MdlAddress,NormalPagePriority);

			if(!InjectInfo)
			{
				status=STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			if(!InjectDll(InjectInfo))
			{
				status=STATUS_UNSUCCESSFUL;
				break;
			}

			status=STATUS_SUCCESS;
			irp->IoStatus.Information=sizeof(INJECT_INFO);

			break;

		default:
			status=STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	irp->IoStatus.Status=status;

	IoCompleteRequest(irp,IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pRegistryPath)
{
	PDEVICE_OBJECT DeviceObject;
	PEPROCESS Process;
	PETHREAD Thread;
	PKAPC_STATE ApcState;

	PVOID KdVersionBlock,NtdllBase;
	PULONG ptr,Functions,Names;
	PUSHORT Ordinals;

	PLDR_DATA_TABLE_ENTRY MmLoadedUserImageList,ModuleEntry;
	ULONG i;

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	pDriverObject->DriverUnload=Unload;

	KdVersionBlock=(PVOID)__readfsdword(0x34); // Get the KdVersionBlock
	MmLoadedUserImageList=*(PLDR_DATA_TABLE_ENTRY*)((PUCHAR)KdVersionBlock+0x228); // Get the MmLoadUserImageList

	DbgPrint("KdVersionBlock address: %#x",KdVersionBlock);
	DbgPrint("MmLoadedUserImageList address: %#x",MmLoadedUserImageList);

	ModuleEntry=(PLDR_DATA_TABLE_ENTRY)MmLoadedUserImageList->InLoadOrderLinks.Flink; // Move to first entry
	NtdllBase=ModuleEntry->DllBase; // ntdll is always located in first entry

	DbgPrint("ntdll base address: %#x",NtdllBase);

	pIDH=(PIMAGE_DOS_HEADER)NtdllBase;
	pINH=(PIMAGE_NT_HEADERS)((PUCHAR)NtdllBase+pIDH->e_lfanew);
	pIED=(PIMAGE_EXPORT_DIRECTORY)((PUCHAR)NtdllBase+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Functions=(PULONG)((PUCHAR)NtdllBase+pIED->AddressOfFunctions);
	Names=(PULONG)((PUCHAR)NtdllBase+pIED->AddressOfNames);

	Ordinals=(PUSHORT)((PUCHAR)NtdllBase+pIED->AddressOfNameOrdinals);

	// Parse the export table to locate LdrLoadDll

	for(i=0;i<pIED->NumberOfNames;i++)
	{
		if(!strcmp((char*)NtdllBase+Names[i],"LdrLoadDll"))
		{
			LdrLoadDll=(PLDR_LOAD_DLL)((PUCHAR)NtdllBase+Functions[Ordinals[i]]);
			break;
		}
	}

	DbgPrint("LdrLoadDll address: %#x",LdrLoadDll);

	Process=PsGetCurrentProcess();
	Thread=PsGetCurrentThread();

	ptr=(PULONG)Thread;

	// Locate the ApcState structure

	for(i=0;i<512;i++)
	{
		if(ptr[i]==(ULONG)Process)
		{
			ApcState=CONTAINING_RECORD(&ptr[i],KAPC_STATE,Process); // Get the actual address of KAPC_STATE
			ApcStateOffset=(ULONG)ApcState-(ULONG)Thread; // Calculate the offset of the ApcState structure

			break;
		}
	}

	DbgPrint("ApcState offset: %#x",ApcStateOffset);

	IoCreateDevice(pDriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&DeviceObject);
	IoCreateSymbolicLink(&SymbolicLink,&DeviceName);

	for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		pDriverObject->MajorFunction[i]=DriverDispatch;
	}

	DeviceObject->Flags&=~DO_DEVICE_INITIALIZING;
	DeviceObject->Flags|=DO_DIRECT_IO;

	DbgPrint("DLL injection driver loaded.");
	return STATUS_SUCCESS;
}
