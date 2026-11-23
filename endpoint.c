#include "Afd.h"

#define AFD_MAX_ENDPOINTS    1024

static KSPIN_LOCK g_EndpointLock;
static BOOLEAN g_EndpointLockInitialized = FALSE;

static AFD_ENDPOINT_CONTEXT g_SampleEndpoint = {
    1, 2, AF_INET, 8080, 0, 0x0100007F, 0, sizeof(AFD_ENDPOINT_CONTEXT)
};

static VOID AfdEnsureLockInitialized(VOID)
{
    if (!g_EndpointLockInitialized) {
        KeInitializeSpinLock(&g_EndpointLock);
        g_EndpointLockInitialized = TRUE;
    }
}

NTSTATUS AfdCreateEndpoint(ULONG *EndpointId)
{
    if (!EndpointId) {
        return STATUS_INVALID_PARAMETER;
    }

    AfdEnsureLockInitialized();
    *EndpointId = 1;
    return STATUS_SUCCESS;
}

NTSTATUS AfdCloseEndpoint(ULONG EndpointId)
{
    KIRQL OldIrql;

    // FIX: Validate endpoint boundary before closing
    if (EndpointId == 0 || EndpointId > AFD_MAX_ENDPOINTS) {
        return STATUS_NOT_FOUND;
    }

    AfdEnsureLockInitialized();
    KeAcquireSpinLock(&g_EndpointLock, &OldIrql);

    // FIX: Safely mark endpoint state to prevent use-after-free during asynchronous teardown
    if (EndpointId == g_SampleEndpoint.EndpointId) {
        g_SampleEndpoint.State = 0; // Inactive
    }

    KeReleaseSpinLock(&g_EndpointLock, OldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS AfdGetContext(ULONG EndpointId, PAFD_ENDPOINT_CONTEXT Context)
{
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Validate EndpointId range to prevent reading uninitialized kernel memory
    if (EndpointId == 0 || EndpointId > AFD_MAX_ENDPOINTS) {
        return STATUS_NOT_FOUND;
    }

    AfdEnsureLockInitialized();
    KeAcquireSpinLock(&g_EndpointLock, &OldIrql);

    if (EndpointId == g_SampleEndpoint.EndpointId && g_SampleEndpoint.State != 0) {
        __try {
            RtlCopyMemory(Context, &g_SampleEndpoint, sizeof(AFD_ENDPOINT_CONTEXT));
            Status = STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }
    }

    KeReleaseSpinLock(&g_EndpointLock, OldIrql);
    return Status;
}

NTSTATUS AfdSetContext(ULONG EndpointId, PAFD_ENDPOINT_CONTEXT Context)
{
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Validate EndpointId range
    if (EndpointId == 0 || EndpointId > AFD_MAX_ENDPOINTS) {
        return STATUS_NOT_FOUND;
    }

    AfdEnsureLockInitialized();
    KeAcquireSpinLock(&g_EndpointLock, &OldIrql);

    if (EndpointId == g_SampleEndpoint.EndpointId && g_SampleEndpoint.State != 0) {
        __try {
            RtlCopyMemory(&g_SampleEndpoint, Context, sizeof(AFD_ENDPOINT_CONTEXT));
            Status = STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }
    }

    KeReleaseSpinLock(&g_EndpointLock, OldIrql);
    return Status;
}
