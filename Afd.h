#ifndef AFD_H
#define AFD_H

#include <ntifs.h>
#include <windef.h>

#ifndef AF_INET
#define AF_INET                     2
#endif

#define AFD_DEVICE_NAME             L"\\Device\\Afd"
#define AFD_DOS_DEVICE_NAME         L"\\DosDevices\\Afd"

#define AFD_DEVICE_TYPE             FILE_DEVICE_NETWORK

// GUID: {394F49B2-2D78-4D0D-B374-1399695455F3}
DEFINE_GUID(GUID_DEVCLASS_AFD,
    0x394F49B2, 0x2D78, 0x4D0D, 0xB3, 0x74, 0x13, 0x99, 0x69, 0x54, 0x55, 0xF3);

// AFD IOCTL Codes (FILE_DEVICE_NETWORK = 0x12)
// CVE-2023-21768: IOCTL_AFD_NOTIFY_SOCK (0x00012127)
#define IOCTL_AFD_NOTIFY_SOCK           0x00012127
#define IOCTL_AFD_BIND                  0x00012003
#define IOCTL_AFD_CONNECT               0x00012007
#define IOCTL_AFD_SEND                  0x0001201F
#define IOCTL_AFD_RECV                  0x00012023
#define IOCTL_AFD_GET_CONTEXT           0x0001203B
#define IOCTL_AFD_SET_CONTEXT           0x0001203F

#pragma pack(push, 1)

// Structure for IOCTL_AFD_NOTIFY_SOCK (CVE-2023-21768)
typedef struct _AFD_NOTIFY_SOCK_REQ {
    HANDLE CompletionPort;
    PVOID CounterAddress; // Vulnerable address targeted by CVE-2023-21768
    ULONG Timeout;
    ULONG EventType;
    ULONG BufferSize;
    PVOID Buffer;
} AFD_NOTIFY_SOCK_REQ, *PAFD_NOTIFY_SOCK_REQ;

typedef struct _AFD_BIND_REQ {
    ULONG ShareType;
    USHORT AddressFamily;
    USHORT Port;
    ULONG IpAddress;
} AFD_BIND_REQ, *PAFD_BIND_REQ;

typedef struct _AFD_CONNECT_REQ {
    USHORT AddressFamily;
    USHORT Port;
    ULONG IpAddress;
    ULONG Flags;
} AFD_CONNECT_REQ, *PAFD_CONNECT_REQ;

typedef struct _AFD_SEND_RECV_REQ {
    PVOID Buffer;
    ULONG BufferLength;
    ULONG Flags;
    ULONG BytesTransferred;
} AFD_SEND_RECV_REQ, *PAFD_SEND_RECV_REQ;

typedef struct _AFD_ENDPOINT_CONTEXT {
    ULONG EndpointId;
    ULONG State;
    USHORT AddressFamily;
    USHORT LocalPort;
    USHORT RemotePort;
    ULONG LocalAddress;
    ULONG RemoteAddress;
    ULONG ContextSize;
} AFD_ENDPOINT_CONTEXT, *PAFD_ENDPOINT_CONTEXT;

#pragma pack(pop)

// Forward declarations
extern PDEVICE_OBJECT g_AfdDeviceObject;

// Prototypes - notify.c
NTSTATUS AfdNotifySocket(PAFD_NOTIFY_SOCK_REQ NotifyReq, ULONG InputLength, ULONG_PTR *Information);
NTSTATUS AfdNotifyRemoveIoCompletion(PVOID CounterAddress);

// Prototypes - endpoint.c
NTSTATUS AfdCreateEndpoint(ULONG *EndpointId);
NTSTATUS AfdCloseEndpoint(ULONG EndpointId);
NTSTATUS AfdGetContext(ULONG EndpointId, PAFD_ENDPOINT_CONTEXT Context);
NTSTATUS AfdSetContext(ULONG EndpointId, PAFD_ENDPOINT_CONTEXT Context);

// Prototypes - transport.c
NTSTATUS AfdValidateTransportBuffer(PVOID Buffer, ULONG BufferLength, BOOLEAN WriteAccess);
NTSTATUS AfdBuildTransportMdl(PVOID Buffer, ULONG BufferLength, PMDL *MdlOut);

#endif // AFD_H
