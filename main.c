#include <ntifs.h>
#include <windef.h>
#include <initguid.h>
#include "Afd.h"

PDEVICE_OBJECT g_AfdDeviceObject = NULL;

VOID AfdUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymlinkName;
    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&SymlinkName, AFD_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&SymlinkName);

    if (g_AfdDeviceObject) {
        IoDeleteDevice(g_AfdDeviceObject);
        g_AfdDeviceObject = NULL;
    }
}

NTSTATUS AfdCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS AfdDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    ULONG IoControlCode;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    PVOID Buffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!Irp) {
        return STATUS_INVALID_PARAMETER;
    }

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    if (!IrpSp) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    Buffer = Irp->AssociatedIrp.SystemBuffer;

    // FIX: Wrap IOCTL dispatch in SEH to guard against unhandled memory faults and invalid buffers
    __try {
        switch (IoControlCode) {
        case IOCTL_AFD_NOTIFY_SOCK: // 0x00012127 (CVE-2023-21768)
            if (Buffer && InputBufferLength >= sizeof(AFD_NOTIFY_SOCK_REQ)) {
                Status = AfdNotifySocket((PAFD_NOTIFY_SOCK_REQ)Buffer, InputBufferLength, &Information);
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_AFD_BIND:
            if (Buffer && InputBufferLength >= sizeof(AFD_BIND_REQ)) {
                Information = sizeof(AFD_BIND_REQ);
                Status = STATUS_SUCCESS;
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_AFD_CONNECT:
            if (Buffer && InputBufferLength >= sizeof(AFD_CONNECT_REQ)) {
                Information = sizeof(AFD_CONNECT_REQ);
                Status = STATUS_SUCCESS;
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_AFD_SEND:
        case IOCTL_AFD_RECV:
            if (Buffer && InputBufferLength >= sizeof(AFD_SEND_RECV_REQ)) {
                PAFD_SEND_RECV_REQ Req = (PAFD_SEND_RECV_REQ)Buffer;
                Status = AfdValidateTransportBuffer(Req->Buffer, Req->BufferLength, (IoControlCode == IOCTL_AFD_RECV));
                if (NT_SUCCESS(Status)) {
                    Information = sizeof(AFD_SEND_RECV_REQ);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_AFD_GET_CONTEXT:
            if (Buffer && OutputBufferLength >= sizeof(AFD_ENDPOINT_CONTEXT)) {
                Status = AfdGetContext(1, (PAFD_ENDPOINT_CONTEXT)Buffer);
                if (NT_SUCCESS(Status)) {
                    Information = sizeof(AFD_ENDPOINT_CONTEXT);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_AFD_SET_CONTEXT:
            if (Buffer && InputBufferLength >= sizeof(AFD_ENDPOINT_CONTEXT)) {
                Status = AfdSetContext(1, (PAFD_ENDPOINT_CONTEXT)Buffer);
                if (NT_SUCCESS(Status)) {
                    Information = sizeof(AFD_ENDPOINT_CONTEXT);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        Information = 0;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymlinkName;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = AfdUnload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = AfdCreateClose;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AfdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AfdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AfdDispatchDeviceControl;

    UNICODE_STRING Sddl;

    RtlInitUnicodeString(&DeviceName, AFD_DEVICE_NAME);
    RtlInitUnicodeString(&SymlinkName, AFD_DOS_DEVICE_NAME);

    // FIX: Secure device creation to mitigate unprivileged access (LOLDrivers: Afd.sys, CVE-2023-21768 / 394f49b2-2d78-4d0d-b374-1399695455f3)
    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA) - Only SYSTEM and Administrators have access
    RtlInitUnicodeString(&Sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    Status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &DeviceName,
        AFD_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &Sddl,
        &GUID_DEVCLASS_AFD,
        &g_AfdDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        // FIX: Clean up device object on symbolic link creation failure to prevent resource leak
        IoDeleteDevice(g_AfdDeviceObject);
        g_AfdDeviceObject = NULL;
        return Status;
    }

    g_AfdDeviceObject->Flags |= DO_BUFFERED_IO;
    g_AfdDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
