using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading;
using System.Media;

namespace MemoryIOLib
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Version 1.0");

            using (MemoryIOLib memoryIO = new MemoryIOLib())
            {
                if (memoryIO.IsInitialized == false)
                {
                    Console.WriteLine("Failed to open device");
                    return;
                }

                // 0xFFFF878274668080 from process explorer (Handles view pane: Ctrl+H)
                // It must be a Handle of Thead type.
                IntPtr ethreadPtr = new IntPtr(unchecked((long)0xFFFF878274668080));

                {
                    IntPtr clientIdPtr = ethreadPtr + 0x648;
                    byte[] buffer = new byte[16];

                    if (memoryIO.ReadMemory(clientIdPtr, buffer) != buffer.Length)
                    {
                        Console.WriteLine("failed to read");
                        return;
                    }

                    long value = BitConverter.ToInt64(buffer, 0);
                    Console.WriteLine("PID: " + value + "(" + value.ToString("x") + ")");
                    value = BitConverter.ToInt64(buffer, 8);
                    Console.WriteLine("TID: " + value + "(" + value.ToString("x") + ")");
                }

                {
                    //    +0x220 Process          : Ptr64 _KPROCESS
                    IntPtr kprocessPosPtr = ethreadPtr + 0x220;
                    byte[] buffer = new byte[8];

                    if (memoryIO.ReadMemory(kprocessPosPtr, buffer) != buffer.Length)
                    {
                        Console.WriteLine("failed to read");
                        return;
                    }

                    IntPtr kprocessPtr = new IntPtr(BitConverter.ToInt64(buffer, 0));
                    Console.WriteLine("_EPROCESS: " + kprocessPtr + "(" + kprocessPtr.ToString("x") + ")");

                    {
                        IntPtr cookiePtr = kprocessPtr + 0x3d0;

                        buffer = new byte[4];

                        if (memoryIO.ReadMemory(cookiePtr, buffer) != buffer.Length)
                        {
                            Console.WriteLine("failed to read");
                            return;
                        }

                        int oldCookie = BitConverter.ToInt32(buffer, 0);
                        Console.WriteLine("[OLD] _EPROCESS.cookie: " + oldCookie + "(" + oldCookie.ToString("x") + ")");

                        int writtenBytes = memoryIO.WriteMemory(cookiePtr, BitConverter.GetBytes(0x5000));
                        Console.WriteLine("Written = " + writtenBytes);

                        memoryIO.ReadMemory(cookiePtr, buffer);
                        int newCookie = BitConverter.ToInt32(buffer, 0);
                        Console.WriteLine("[NEW] _EPROCESS.cookie: " + newCookie + "(" + newCookie.ToString("x") + ")");

                        memoryIO.WriteMemory(cookiePtr, BitConverter.GetBytes(oldCookie));
                        Console.WriteLine("Written = " + writtenBytes);
                    }
                }

                //Console.WriteLine($"Current Position: {memoryIO.Position}(" + memoryIO.Position.ToString("x") + ")");

                //memoryIO.Position = ethreadPtr;
                //Console.WriteLine($"Current Position: {memoryIO.Position}(" + memoryIO.Position.ToString("x") + ")");
            }
        }
    }
}
