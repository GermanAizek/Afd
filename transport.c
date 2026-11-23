#include "Afd.h"

#define AFD_MAX_TRANSPORT_BUFFER_SIZE (16 * 1024 * 1024) // 16 MB

// FIX: Validate transport buffer address limits and probe user memory before transferring
NTSTATUS AfdValidateTransportBuffer(PVOID Buffer, ULONG BufferLength, BOOLEAN WriteAccess)
{
    if (!Buffer || BufferLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Limit buffer length to prevent non-paged pool resource exhaustion
    if (BufferLength > AFD_MAX_TRANSPORT_BUFFER_SIZE) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Ensure entire range is within user-mode memory
    if ((ULONG_PTR)Buffer + BufferLength < (ULONG_PTR)Buffer ||
        (ULONG_PTR)Buffer + BufferLength > (ULONG_PTR)MmHighestUserAddress) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        if (WriteAccess) {
            ProbeForWrite(Buffer, BufferLength, sizeof(UCHAR));
        } else {
            ProbeForRead(Buffer, BufferLength, sizeof(UCHAR));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

// FIX: Safely allocate and lock MDL pages with exception handling to prevent non-paged pool corruption
NTSTATUS AfdBuildTransportMdl(PVOID Buffer, ULONG BufferLength, PMDL *MdlOut)
{
    PMDL Mdl;
    NTSTATUS Status;

    if (!Buffer || BufferLength == 0 || !MdlOut) {
        return STATUS_INVALID_PARAMETER;
    }

    *MdlOut = NULL;

    Status = AfdValidateTransportBuffer(Buffer, BufferLength, FALSE);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Mdl = IoAllocateMdl(Buffer, BufferLength, FALSE, FALSE, NULL);
    if (!Mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(Mdl, UserMode, IoReadAccess);
        *MdlOut = Mdl;
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(Mdl);
        return GetExceptionCode();
    }
}
