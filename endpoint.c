#include "Afd.h"

static AFD_ENDPOINT_CONTEXT g_SampleEndpoint = {
    1, 2, AF_INET, 8080, 0, 0x0100007F, 0, sizeof(AFD_ENDPOINT_CONTEXT)
};

NTSTATUS AfdCreateEndpoint(ULONG *EndpointId)
{
    if (!EndpointId) {
        return STATUS_INVALID_PARAMETER;
    }

    *EndpointId = 1;
    return STATUS_SUCCESS;
}

NTSTATUS AfdCloseEndpoint(ULONG EndpointId)
{
    UNREFERENCED_PARAMETER(EndpointId);
    return STATUS_SUCCESS;
}

NTSTATUS AfdGetContext(ULONG EndpointId, PAFD_ENDPOINT_CONTEXT Context)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initial implementation without endpoint list synchronization
    if (EndpointId == g_SampleEndpoint.EndpointId) {
        RtlCopyMemory(Context, &g_SampleEndpoint, sizeof(AFD_ENDPOINT_CONTEXT));
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS AfdSetContext(ULONG EndpointId, PAFD_ENDPOINT_CONTEXT Context)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initial implementation without validation
    if (EndpointId == g_SampleEndpoint.EndpointId) {
        RtlCopyMemory(&g_SampleEndpoint, Context, sizeof(AFD_ENDPOINT_CONTEXT));
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}
