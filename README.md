# Afd

Afd (Afd.sys / Windows Ancillary Function Driver for WinSock) - Windows kernel-mode driver providing the core socket endpoint and networking interface between user-mode Winsock DLLs (mswsock.dll, ws2_32.dll) and kernel transport providers (tcpip.sys).

My opensource driver does not use the original source codes and is a reverse-engineered driver using [Ghidra](https://en.wikipedia.org/wiki/Ghidra) and [Radare2](https://en.wikipedia.org/wiki/Radare2). The rights have not been violated, and the new driver cannot be signed due to the EV certificate. I hope that the vulnerabilities can be closed using my security patches.

The main goal of the project is to recreate a secure driver with fixed vulnerabilities and errors made by past developers.

### Functions

Driver Afd.sys manages Winsock socket endpoints, asynchronous I/O completion notifications, and network buffers:

- Asynchronous socket I/O notification dispatching and completion tracking (IOCTL 0x00012127)
- Socket address family binding and port allocation (IOCTL 0x00012003)
- Transport connection initiation and state machine management (IOCTL 0x00012007)
- Network data packet transmission and receipt via transport buffers (IOCTL 0x0001201F, 0x00012023)
- Socket endpoint context retrieval and updating (IOCTL 0x0001203B, 0x0001203F)

Fixed vulnerabilities in opensource driver Afd.sys:

- [ ] [LOLDrivers: Afd.sys](https://www.loldrivers.io/drivers/394f49b2-2d78-4d0d-b374-1399695455f3/)
  - Elevation of Privilege via missing ProbeForWrite in AfdNotifySocket / AfdNotifyRemoveIoCompletion (CVE-2023-21768). Low-privilege users can pass arbitrary kernel addresses in CounterAddress to achieve arbitrary kernel write, corrupt Windows I/O Ring objects or PreviousMode, and elevate privileges to NT AUTHORITY\SYSTEM (BYOVD, MITRE ATT&CK T1068).

Fixed no publish vulnerabilities and bugs which contributors to this project found:

- [ ] Device deletion bypassed on symbolic link creation failure ([view code](main.c))
- [ ] Arbitrary kernel memory write and missing ProbeForWrite in command 0x00012127 ([view code](notify.c))
- [ ] Socket endpoint use-after-free and context corruption in command 0x0001203B ([view code](endpoint.c))
- [ ] Unchecked MDL allocation and non-paged pool memory exhaustion in command 0x0001201F ([view code](transport.c))
- [ ] Unhandled exception and NULL pointer dereference in control dispatching ([view code](main.c))
- [ ] Device creation with weak permissions ([view code](main.c))

Authors:

- 2026 - Herman Semenoff <<GermanAizek@yandex.ru>> ([germanaizek.github.io](https://germanaizek.github.io))
- Microsoft Corporation <<secure@microsoft.com>>
