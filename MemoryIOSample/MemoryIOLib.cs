using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Net;

namespace MemoryIOLib
{
    class MemoryIOLib : IDisposable
    {
        const uint IOCTL_READ_MEMORY = 0x9c402410;
        const uint IOCTL_WRITE_MEMORY = 0x9c402414;
        const uint IOCTL_GETPOS_MEMORY = 0x9c402418;
        const uint IOCTL_SETPOS_MEMORY = 0x9c40241c;

        SafeFileHandle fileHandle;

        public MemoryIOLib()
        {
            InitializeDevice();
        }
            
        public bool InitializeDevice()
        {
            Dispose();

            fileHandle = Kernel32.CreateFile(@"\\.\KernelMemoryIO", NativeFileAccess.FILE_GENERIC_READ,
                NativeFileShare.NONE, IntPtr.Zero, NativeFileMode.OPEN_EXISTING, NativeFileFlag.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (fileHandle.IsInvalid == true)
            {
                return false;
            }

            return true;
        }

        public void Dispose()
        {
            if (fileHandle != null)
            {
                fileHandle.Close();
                fileHandle = null;
            }
        }

        public bool IsInitialized
        {
            get
            {
                return fileHandle != null && fileHandle.IsInvalid == false;
            }
        }

        public IntPtr Position
        {
            get
            {
                if (this.IsInitialized == false)
                {
                    return IntPtr.Zero;
                }

                byte[] addressBytes = new byte[IntPtr.Size];
                int pBytesReturned;

                if (Kernel32.DeviceIoControl(fileHandle, IOCTL_GETPOS_MEMORY,
                    null, 0, addressBytes, addressBytes.Length, out pBytesReturned, IntPtr.Zero) == true)
                {
                    if (IntPtr.Size == 8)
                    {
                        return new IntPtr(BitConverter.ToInt64(addressBytes, 0));
                    }

                    return new IntPtr(BitConverter.ToInt32(addressBytes, 0));
                }

                return IntPtr.Zero;
            }
            set
            {
                if (this.IsInitialized == false)
                {
                    return;
                }

                byte[] addressBytes = null;

                if (IntPtr.Size == 8)
                {
                    addressBytes = BitConverter.GetBytes(value.ToInt64());
                }
                else
                {
                    addressBytes = BitConverter.GetBytes(value.ToInt32());
                }

                int pBytesReturned;

                Kernel32.DeviceIoControl(fileHandle, IOCTL_SETPOS_MEMORY, addressBytes, addressBytes.Length, null, 9,
                    out pBytesReturned, IntPtr.Zero);
            }
        }

        internal int WriteMemory(IntPtr ptr, byte[] buffer)
        {
            if (this.IsInitialized == false)
            {
                return 0;
            }

            this.Position = ptr;
            int pBytesReturned;

            if (Kernel32.DeviceIoControl(fileHandle, IOCTL_WRITE_MEMORY, buffer, buffer.Length,
                null, 0, out pBytesReturned, IntPtr.Zero) == true)
            {
                return pBytesReturned;
            }

            return 0;
        }

        public int ReadMemory(IntPtr position, byte [] buffer)
        {
            if (this.IsInitialized == false)
            {
                return 0;
            }

            byte[] addressBytes = null;

            if (IntPtr.Size == 8)
            {
                addressBytes = BitConverter.GetBytes(position.ToInt64());
            }
            else
            {
                addressBytes = BitConverter.GetBytes(position.ToInt32());
            }

            int pBytesReturned;

            if (Kernel32.DeviceIoControl(fileHandle, IOCTL_READ_MEMORY, addressBytes, addressBytes.Length,
                buffer, buffer.Length,
                out pBytesReturned, IntPtr.Zero) == true)
            {
                return pBytesReturned;
            }

            return 0;
        }
    }
}
