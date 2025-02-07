
#include <ntddk.h>
#include <strsafe.h>

#ifdef __cplusplus
extern "C"
{
#endif
    NTSTATUS MajorDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
    NTSTATUS MajorCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS MajorClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
    NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
#ifdef __cplusplus
}
#endif

#include "MemoryIO.h"

#define CONFIG_CMD(bus, dev_fn, where) \
 (0x80000000 | (((ULONG)(bus)) << 16) | (((dev_fn) & 0x1F) << 11) | (((dev_fn) & 0xE0) << 3) | ((where) & ~3))

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING uniDOSString;

    RtlInitUnicodeString(&uniDOSString, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&uniDOSString);
    IoDeleteDevice(pDriverObject->DeviceObject);

    DbgPrint("KernelMemoryIO Driver Unloaded\n");
}

// WARNING!!!
// This driver must not be deployed in your product.
// Definitely, you shouldn't sign this module except only in case of testing or studying.
//
// Allowing user-mode program to read and write memory in kernel space has seriously security vulnerabilities.

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    NTSTATUS ntStatus;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING uniNameString, uniDOSString;

    RtlInitUnicodeString(&uniNameString, DEVICE_NAME);
    RtlInitUnicodeString(&uniDOSString, DOS_DEVICE_NAME);

    ntStatus = IoCreateDevice(pDriverObject,
        sizeof(MEMORYIO_DEVICE_EXTENSION),
        &uniNameString,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);

    if (NT_SUCCESS(ntStatus) == FALSE)
    {
        return ntStatus;
    }

    PMEMORYIO_DEVICE_EXTENSION deviceExtension = (PMEMORYIO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    deviceExtension->Position = NULL;

    ntStatus = IoCreateSymbolicLink(&uniDOSString, &uniNameString);

    if (NT_SUCCESS(ntStatus) == FALSE)
    {
        return ntStatus;
    }

    pDriverObject->MajorFunction[IRP_MJ_CREATE] = MajorCreate;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MajorDeviceControl;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorClose;
    pDriverObject->DriverUnload = DriverUnload;

    DbgPrint("KernelMemoryIO Driver loaded\n");

    return STATUS_SUCCESS;
}

PUCHAR BytesToPtr(PVOID ioBuffer)
{
    PUCHAR copyPtr = NULL;

#if defined(_AMD64_)
    memcpy(&(__int64)copyPtr, ioBuffer, 8);
#else
    memcpy(&copyPtr, ioBuffer, 8);
#endif

    return copyPtr;
}

NTSTATUS MajorDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION  irpSp;
    NTSTATUS            ntStatus = STATUS_SUCCESS;

    ULONG               inBufLength;   /* Input buffer length */
    ULONG               outBufLength;  /* Output buffer length */
    PVOID               ioBuffer;

    ULONG ptrSize = sizeof(void*);

    irpSp = IoGetCurrentIrpStackLocation(pIrp);

    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
    pIrp->IoStatus.Information = 0; /* Output Buffer Size */

    PMEMORYIO_DEVICE_EXTENSION deviceExtension = (PMEMORYIO_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
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

            pIrp->IoStatus.Information = 1; /* Output Buffer Size */
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

            pIrp->IoStatus.Information = 2; /* Output Buffer Size */
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_READ_PORT_ULONG:
            if ((inBufLength >= 4) && (outBufLength >= 4))
            {
                ULONG portBuffer = *(PULONG)ioBuffer;
                PULONG longBuffer = (PULONG)ioBuffer;

                longBuffer[0] = READ_PORT_ULONG((PULONG)portBuffer);
                DbgPrint("IOCTL_READ_PORT_ULONG: port: %x, cmd: %x\n", portBuffer,
                    longBuffer[1]);
            }
            else
            {
                ntStatus = STATUS_BUFFER_TOO_SMALL;
            }

            pIrp->IoStatus.Information = 4; /* Output Buffer Size */
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

            pIrp->IoStatus.Information = 0; /* Output Buffer Size */
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

            pIrp->IoStatus.Information = 0; /* Output Buffer Size */
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

            pIrp->IoStatus.Information = 0; /* Output Buffer Size */
            ntStatus = STATUS_SUCCESS;
            break;

        case IOCTL_KMIO_TEST:
            {
                ULONG configCmd = CONFIG_CMD(0, 0, 0);
                ULONG port = 0xcf8;
                WRITE_PORT_ULONG((ULONG*)port, configCmd);
                ULONG result = READ_PORT_ULONG((ULONG*)0xcfc);

                DbgPrint("KernelMemoryIO Test: port: %x, cmd: %x, %d, %x\n", port, configCmd, result, result);

                pIrp->IoStatus.Information = 0; /* Output Buffer Size */
                ntStatus = STATUS_SUCCESS;
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
                PUCHAR ptr = BytesToPtr(ioBuffer);

                /*
                deviceExtension->Position = ptr;

                PUCHAR outBuffer = (PUCHAR)ioBuffer;
                for (ULONG i = 0; i < outBufLength; i++)
                {
                    outBuffer[i] = *(ptr + i);
                }
                numberOfBytesTransferred = outBufLength;
                */

                /*
                // For Windows 7
                deviceExtension->Position = ptr;
                RtlCopyMemory(ioBuffer, deviceExtension->Position, outBufLength);
                numberOfBytesTransferred = outBufLength;
                */

                MM_COPY_ADDRESS address;
                address.VirtualAddress = ptr;
                MmCopyMemory(ioBuffer, address, outBufLength, MM_COPY_MEMORY_VIRTUAL, &numberOfBytesTransferred);

                pIrp->IoStatus.Information = numberOfBytesTransferred;
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

                /*
                // For Windows 7
                RtlCopyMemory(ioBuffer, &deviceExtension->Position, ptrSize);
                numberOfBytesTransferred = ptrSize;
                */

                MM_COPY_ADDRESS address;
                address.VirtualAddress = &deviceExtension->Position;
                MmCopyMemory(ioBuffer, address, ptrSize, MM_COPY_MEMORY_VIRTUAL, &numberOfBytesTransferred);

                pIrp->IoStatus.Information = numberOfBytesTransferred;
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
                PUCHAR ptr = BytesToPtr(ioBuffer);
                deviceExtension->Position = ptr;

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
                PUCHAR ptr = deviceExtension->Position;

                /*
                PUCHAR inBuffer = (PUCHAR)ioBuffer;
                for (ULONG i = 0; i < inBufLength; i++)
                {
                    *(ptr + i) = inBuffer[i];
                }
                */

                /*
                // For Windows 7
                RtlCopyMemory(deviceExtension->Position, ioBuffer, inBufLength);
                numberOfBytesTransferred = inBufLength;
                */

                MM_COPY_ADDRESS address;
                address.VirtualAddress = ioBuffer;
                MmCopyMemory(ptr, address, inBufLength, MM_COPY_MEMORY_VIRTUAL, &numberOfBytesTransferred);

                pIrp->IoStatus.Information = numberOfBytesTransferred;
                ntStatus = STATUS_SUCCESS;
            }
            break;

        default:
            ntStatus = STATUS_UNSUCCESSFUL;
            break;
    }

    pIrp->IoStatus.Status = ntStatus;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return ntStatus;
}

NTSTATUS MajorCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    NTSTATUS ntStatus;

    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = STATUS_SUCCESS;

    ntStatus = pIrp->IoStatus.Status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS MajorClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    NTSTATUS ntStatus;

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    ntStatus = pIrp->IoStatus.Status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return ntStatus;
}