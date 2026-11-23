#include "Afd.h"

// FIX: Remediate arbitrary kernel write (CVE-2023-21768 / LOLDrivers: Afd.sys, 394f49b2-2d78-4d0d-b374-1399695455f3)
// Enforce user-mode address verification, alignment checks, and ProbeForWrite before updating completion counter
NTSTATUS AfdNotifyRemoveIoCompletion(PVOID CounterAddress)
{
    if (!CounterAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    // Verify address range is strictly within user-mode space
    if ((ULONG_PTR)CounterAddress + sizeof(ULONG) < (ULONG_PTR)CounterAddress ||
        (ULONG_PTR)CounterAddress + sizeof(ULONG) > (ULONG_PTR)MmHighestUserAddress) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Check ULONG alignment
    if (((ULONG_PTR)CounterAddress & (sizeof(ULONG) - 1)) != 0) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    __try {
        // Probe user-mode memory before writing to prevent kernel-space corruption
        ProbeForWrite(CounterAddress, sizeof(ULONG), sizeof(ULONG));
        *(PULONG)CounterAddress = *(PULONG)CounterAddress + 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

NTSTATUS AfdNotifySocket(PAFD_NOTIFY_SOCK_REQ NotifyReq, ULONG InputLength, ULONG_PTR *Information)
{
    NTSTATUS Status;

    if (!NotifyReq || InputLength < sizeof(AFD_NOTIFY_SOCK_REQ)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // FIX: Validate optional user notification buffer
    if (NotifyReq->Buffer && NotifyReq->BufferSize > 0) {
        if ((ULONG_PTR)NotifyReq->Buffer + NotifyReq->BufferSize < (ULONG_PTR)NotifyReq->Buffer ||
            (ULONG_PTR)NotifyReq->Buffer + NotifyReq->BufferSize > (ULONG_PTR)MmHighestUserAddress) {
            return STATUS_ACCESS_VIOLATION;
        }

        __try {
            ProbeForRead(NotifyReq->Buffer, NotifyReq->BufferSize, sizeof(UCHAR));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    // Safely update completion counter
    Status = AfdNotifyRemoveIoCompletion(NotifyReq->CounterAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (Information) {
        *Information = sizeof(AFD_NOTIFY_SOCK_REQ);
    }

    return STATUS_SUCCESS;
}
