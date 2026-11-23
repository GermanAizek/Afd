#include "Afd.h"

NTSTATUS AfdNotifyRemoveIoCompletion(PVOID CounterAddress)
{
    // Initial vulnerable implementation (CVE-2023-21768):
    // Missing ProbeForWrite allows arbitrary kernel write to CounterAddress
    if (CounterAddress) {
        *(PULONG)CounterAddress = *(PULONG)CounterAddress + 1;
    }

    return STATUS_SUCCESS;
}

NTSTATUS AfdNotifySocket(PAFD_NOTIFY_SOCK_REQ NotifyReq, ULONG InputLength, ULONG_PTR *Information)
{
    if (!NotifyReq || InputLength < sizeof(AFD_NOTIFY_SOCK_REQ)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Direct invocation with unvalidated user pointer
    AfdNotifyRemoveIoCompletion(NotifyReq->CounterAddress);

    if (Information) {
        *Information = sizeof(AFD_NOTIFY_SOCK_REQ);
    }

    return STATUS_SUCCESS;
}
