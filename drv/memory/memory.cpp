#include "memory.h"
#include <core/framework.h>
#include <process/funcs.h>



NTSTATUS memory::write_process_memory(uint32_t pid, uint32_t user_pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_written)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS user_proc = process::get_by_id(user_pid, &status);
	if (!NT_SUCCESS(status)) return status;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(user_proc);
		return status;
	}

	size_t processed;
	status = memory::MmCopyVirtualMemory(user_proc, (void *)buffer, target_proc, (void *)addr, size, UserMode, &processed);

	ObDereferenceObject(user_proc);
	ObDereferenceObject(target_proc);

	if (!NT_SUCCESS(status)) return status;
	if (bytes_written) *bytes_written = processed;

	if (processed != size)
		return STATUS_FAIL_CHECK;
	return STATUS_SUCCESS;
}

NTSTATUS memory::read_process_memory(uint32_t pid, uint32_t user_pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_read)
{
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS user_proc = process::get_by_id(user_pid, &status);
	if (!NT_SUCCESS(status)) return status;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status)) return status;

	size_t processed;
	status = memory::MmCopyVirtualMemory(target_proc, (void *)addr, user_proc, (void *)buffer, size, UserMode, &processed);
	if (!NT_SUCCESS(status)) return status;
	if (bytes_read) *bytes_read = processed;

	if (processed != size)
		return STATUS_FAIL_CHECK;
	return STATUS_SUCCESS;
}

//from https://www.unknowncheats.me/forum/valorant/495965-bypass-guarded-region-externally.html
auto find_guarded_region() -> UINT_PTR
{
    PSYSTEM_BIGPOOL_INFORMATION pool_information = 0;

    ULONG information_length = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, &information_length, 0, &information_length);

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (pool_information)
            ExFreePool(pool_information);

        pool_information = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, information_length);
        status = ZwQuerySystemInformation(SystemBigPoolInformation, pool_information, information_length, &information_length);
    }
    UINT_PTR saved_virtual_address = 0;

    if (pool_information)
    {
        for (ULONG i = 0; i < pool_information->Count; i++)
        {
            SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];

            UINT_PTR virtual_address = (UINT_PTR)allocation_entry->VirtualAddress & ~1ull;

            if (allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000)
            {
                if (saved_virtual_address == 0 && allocation_entry->TagUlong == 'TnoC') {
                    saved_virtual_address = virtual_address;
                }
            }
        }

        ExFreePool(pool_information);
    }
    return saved_virtual_address;
}