
#include <ntddk.h>
#include <wdf.h>
#include <strsafe.h>

#ifdef __cplusplus
extern "C"
{
#endif
    DRIVER_INITIALIZE DriverEntry;
    EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;
    EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
#ifdef __cplusplus
}
#endif

#include "MemoryIO.h"

#define CONFIG_CMD(bus, dev_fn, where) \
 (0x80000000 | (((ULONG)(bus)) << 16) | (((dev_fn) & 0x1F) << 11) | (((dev_fn) & 0xE0) << 3) | ((where) & ~3))

VOID EvtDriverUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    DbgPrint("KernelMemoryIO Driver Unloaded\n");
}

// WARNING!!!
// This driver must not be deployed in your product.
// Definitely, you shouldn't sign this module except only in case of testing or studying.
//
// Allowing user-mode program to read and write memory in kernel space has seriously security vulnerabilities.

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS ntStatus;
    WDFDRIVER driver;
    WDFDEVICE device;
    PWDFDEVICE_INIT deviceInit;
    WDF_DRIVER_CONFIG driverConfig;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    UNICODE_STRING uniNameString;
    UNICODE_STRING uniDOSString;

    WDF_DRIVER_CONFIG_INIT(&driverConfig, WDF_NO_EVENT_CALLBACK);
    driverConfig.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driverConfig.EvtDriverUnload = EvtDriverUnload;

    ntStatus = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &driverConfig, &driver);
    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
    if (deviceInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(deviceInit, TRUE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    RtlInitUnicodeString(&uniNameString, DEVICE_NAME);
    ntStatus = WdfDeviceInitAssignName(deviceInit, &uniNameString);
    if (!NT_SUCCESS(ntStatus))
    {
        WdfDeviceInitFree(deviceInit);
        return ntStatus;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    ntStatus = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    PDEVICE_CONTEXT deviceContext = DeviceGetContext(device);
    deviceContext->Position = NULL;

    RtlInitUnicodeString(&uniDOSString, DOS_DEVICE_NAME);
    ntStatus = WdfDeviceCreateSymbolicLink(device, &uniDOSString);
    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    ntStatus = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(ntStatus))
    {
        return ntStatus;
    }

    WdfControlFinishInitializing(device);

    DbgPrint("KernelMemoryIO Driver loaded\n");

    return STATUS_SUCCESS;
}

PUCHAR BytesToPtr(PVOID ioBuffer, int ptrSize)
{
    PUCHAR copyPtr = NULL;

#if defined(_AMD64_)
    memcpy(&(__int64)copyPtr, ioBuffer, ptrSize);
#else
    memcpy(&copyPtr, ioBuffer, ptrSize);
#endif

    return copyPtr;
}

VOID EvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    size_t bytesReturned = 0;
    PVOID ioBuffer = NULL;

    ULONG inBufLength = (ULONG)InputBufferLength;
    ULONG outBufLength = (ULONG)OutputBufferLength;
    ULONG ptrSize = sizeof(void*);

    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PDEVICE_CONTEXT deviceContext = DeviceGetContext(device);

    // For METHOD_BUFFERED, input and output buffers share the same system buffer.
    // Retrieve via either function; both return the same pointer.
    if (InputBufferLength > 0)
    {
        ntStatus = WdfRequestRetrieveInputBuffer(Request, 0, &ioBuffer, NULL);
    }
    else if (OutputBufferLength > 0)
    {
        ntStatus = WdfRequestRetrieveOutputBuffer(Request, 0, &ioBuffer, NULL);
    }

    if (!NT_SUCCESS(ntStatus))
    {
        WdfRequestComplete(Request, ntStatus);
        return;
    }

    switch (IoControlCode)
    {
        case IOCTL_READ_PORT_UCHAR:
            if ((inBufLength >= 1) && (outBufLength >= 1))
            {
                UCHAR portBuffer = *(PUCHAR)ioBuffer;
                PUCHAR dataBuffer = (PUCHAR)ioBuffer;

                dataBuffer[0] = READ_PORT_UCHAR((PUCHAR)portBuffer);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            bytesReturned = 1;
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_READ_PORT_USHORT:
            if ((inBufLength >= 2) && (outBufLength >= 2))
            {
                USHORT portBuffer = *(PUSHORT)ioBuffer;
                PUSHORT shortBuffer = (PUSHORT)ioBuffer;

                shortBuffer[0] = READ_PORT_USHORT((PUSHORT)portBuffer);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            bytesReturned = 2;
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_READ_PORT_ULONG:
            if ((inBufLength >= 4) && (outBufLength >= 4))
            {
                ULONG portBuffer = *(PULONG)ioBuffer;
                PULONG longBuffer = (PULONG)ioBuffer;

                longBuffer[0] = READ_PORT_ULONG((PULONG)portBuffer);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            bytesReturned = 4;
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_WRITE_PORT_UCHAR:
            if (inBufLength >= 3)
            {
                PUSHORT portBuffer = (PUSHORT)ioBuffer;
                PUCHAR dataBuffer = (PUCHAR)ioBuffer;

                WRITE_PORT_UCHAR((PUCHAR)portBuffer[0], dataBuffer[2]);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            bytesReturned = 0;
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_WRITE_PORT_USHORT:
            if (inBufLength >= 4)
            {
                PUSHORT portBuffer = (PUSHORT)ioBuffer;
                PUSHORT dataBuffer = (PUSHORT)ioBuffer;

                WRITE_PORT_USHORT((PUSHORT)portBuffer, dataBuffer[1]);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            bytesReturned = 0;
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_WRITE_PORT_ULONG:
            if (inBufLength >= 8)
            {
                PULONG portBuffer = (PULONG)ioBuffer;
                PULONG dataBuffer = (PULONG)ioBuffer;

                WRITE_PORT_ULONG((PULONG)portBuffer[0], dataBuffer[1]);

                DbgPrint("KernelMemoryIO Test: port: %x, cmd: %x\n", portBuffer[0],
                    dataBuffer[1]);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            bytesReturned = 0;
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_KMIO_TEST:
            {
                // MmMapIoSpaceEx(0x80000000, 0x1000, MmNonCached);
            }
            break;

        case IOCTL_READ_PHYSICAL_MEMORY:
            if (inBufLength != ptrSize)
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                PVOID physicalAddress = (PVOID)BytesToPtr(ioBuffer, ptrSize);

                SIZE_T numberOfBytesTransferred = 0;
                MM_COPY_ADDRESS address = { 0 };
                address.PhysicalAddress.QuadPart = (ULONGLONG)physicalAddress;

                ntStatus = MmCopyMemory(ioBuffer, address, outBufLength, MM_COPY_MEMORY_PHYSICAL, &numberOfBytesTransferred);

                if (ntStatus != STATUS_SUCCESS)
                {
                    DbgPrint("KernelMemoryIO: MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) failed: %x\n", ntStatus);

                    PVOID ecamAddress = MmMapIoSpace(address.PhysicalAddress, outBufLength, MmNonCached);
                    if (ecamAddress != NULL)
                    {
                        RtlCopyMemory(ioBuffer, ecamAddress, outBufLength);
                        MmUnmapIoSpace(ecamAddress, outBufLength);

                        bytesReturned = outBufLength;
                        ntStatus = STATUS_SUCCESS;
                    }
                }
                else
                {
                    bytesReturned = numberOfBytesTransferred;
                }
            }
            break;

        case IOCTL_READ_MEMORY:
            if (inBufLength != ptrSize)
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                SIZE_T numberOfBytesTransferred = 0;
                PUCHAR ptr = BytesToPtr(ioBuffer, ptrSize);

                MM_COPY_ADDRESS address;
                address.VirtualAddress = ptr;
                MmCopyMemory(ioBuffer, address, outBufLength, MM_COPY_MEMORY_VIRTUAL, &numberOfBytesTransferred);

                bytesReturned = numberOfBytesTransferred;
                ntStatus = STATUS_SUCCESS;
            }
            break;

        case IOCTL_GETPOS_MEMORY:
            if (outBufLength != ptrSize)
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                SIZE_T numberOfBytesTransferred = 0;

                MM_COPY_ADDRESS address;
                address.VirtualAddress = &deviceContext->Position;
                MmCopyMemory(ioBuffer, address, ptrSize, MM_COPY_MEMORY_VIRTUAL, &numberOfBytesTransferred);

                bytesReturned = numberOfBytesTransferred;
                ntStatus = STATUS_SUCCESS;
            }
            break;

        case IOCTL_SETPOS_MEMORY:
            if (inBufLength != ptrSize)
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                PUCHAR ptr = BytesToPtr(ioBuffer, ptrSize);
                deviceContext->Position = ptr;

                ntStatus = STATUS_SUCCESS;
            }
            break;

        case IOCTL_WRITE_MEMORY:
            if (inBufLength == 0)
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                SIZE_T numberOfBytesTransferred = 0;
                PUCHAR ptr = deviceContext->Position;

                MM_COPY_ADDRESS address;
                address.VirtualAddress = ioBuffer;
                MmCopyMemory(ptr, address, inBufLength, MM_COPY_MEMORY_VIRTUAL, &numberOfBytesTransferred);

                bytesReturned = numberOfBytesTransferred;
                ntStatus = STATUS_SUCCESS;
            }
            break;

        default:
            ntStatus = STATUS_UNSUCCESSFUL;
            break;
    }

    WdfRequestCompleteWithInformation(Request, ntStatus, bytesReturned);
}
