#include "Afd.h"

NTSTATUS AfdValidateTransportBuffer(PVOID Buffer, ULONG BufferLength, BOOLEAN WriteAccess)
{
    UNREFERENCED_PARAMETER(WriteAccess);

    if (!Buffer || BufferLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initial implementation without memory probe
    return STATUS_SUCCESS;
}

NTSTATUS AfdBuildTransportMdl(PVOID Buffer, ULONG BufferLength, PMDL *MdlOut)
{
    PMDL Mdl;

    if (!Buffer || BufferLength == 0 || !MdlOut) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initial implementation: allocate MDL without checking pool exhaust limits
    Mdl = IoAllocateMdl(Buffer, BufferLength, FALSE, FALSE, NULL);
    if (!Mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *MdlOut = Mdl;
    return STATUS_SUCCESS;
}
