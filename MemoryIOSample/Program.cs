using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading;
using System.Media;
using KernelStructOffset;
using System.Diagnostics;

namespace MemoryIOLib
{
    class Program
    {
        // Prerequisite:
        //  Register and start "KernelMemoryIO" kernel driver
        //  https://github.com/stjeong/KernelMemoryIO/tree/master/KernelMemoryIO
        //
        // sc create "KernelMemoryIO" binPath= "D:\Debug\KernelMemoryIO.sys" type= kernel start= demand
        // sc delete "KernelMemoryIO"
        // net start KernelMemoryIO
        // net stop KernelMemoryIO

        static void Main(string[] args)
        {
            Console.WriteLine("Version 1.0");

            int processId = Process.GetCurrentProcess().Id;

            using (KernelMemoryIO memoryIO = new KernelMemoryIO())
            {
                if (memoryIO.IsInitialized == false)
                {
                    Console.WriteLine("Failed to open device");
                    return;
                }

                /*
                // 0xFFFF850953C62080 from process explorer (Handles view pane: Ctrl+H)
                // It must be a Handle of Thead type.
                IntPtr ethreadPtr = new IntPtr(unchecked((long)0xFFFF850953C62080));
                */

                IntPtr ethreadPtr = GetEThread();

                var ethreadOffset = DbgOffset.Get("_ETHREAD");
                var kthreadOffset = DbgOffset.Get("_KTHREAD");
                var eprocessOffset = DbgOffset.Get("_EPROCESS");

                {
                    //    +0x648 Cid : _CLIENT_ID
                    IntPtr clientIdPtr = ethreadOffset.GetPointer(ethreadPtr, "Cid");
                    _CLIENT_ID cid = memoryIO.ReadMemory<_CLIENT_ID>(clientIdPtr);

                    if (cid.UniqueProcess.ToInt32() != processId)
                    {
                        Console.WriteLine("failed to read");
                        return;
                    }

                    Console.WriteLine($"PID: {cid.Pid} ({cid.Pid:x})");
                    Console.WriteLine($"TID: {cid.Tid} ({cid.Tid:x})");
                }

                {
                    //    +0x220 Process : Ptr64 _KPROCESS
                    IntPtr kprocessPosPtr = kthreadOffset.GetPointer(ethreadPtr, "Process");

                    IntPtr kprocessPtr = memoryIO.ReadMemory<IntPtr>(kprocessPosPtr);
                    Console.WriteLine($"_EPROCESS: {kprocessPtr} ({kprocessPtr:x})");

                    {
                        // +0x3d0 Cookie : Uint4B
                        IntPtr cookiePtr = eprocessOffset.GetPointer(kprocessPtr, "Cookie");
                        int oldCookie = memoryIO.ReadMemory<int>(cookiePtr);
                        Console.WriteLine($"[OLD] _EPROCESS.cookie: {oldCookie}({oldCookie:x})");

                        int writtenBytes = memoryIO.WriteMemory<int>(cookiePtr, 0x5000);
                        Console.WriteLine("Written = " + writtenBytes);

                        int newCookie = memoryIO.ReadMemory<int>(cookiePtr);
                        Console.WriteLine($"[NEW] _EPROCESS.cookie: {newCookie}({newCookie:x})");

                        memoryIO.WriteMemory<int>(cookiePtr, oldCookie);
                        Console.WriteLine("Written = " + writtenBytes);
                    }
                }

                //Console.WriteLine($"Current Position: {memoryIO.Position}({memoryIO.Position:x})");

                //memoryIO.Position = ethreadPtr;
                //Console.WriteLine($"Current Position: {memoryIO.Position}({memoryIO.Position:x})");
            }
        }

        private static IntPtr GetEThread()
        {
            int processId = Process.GetCurrentProcess().Id;

            using (WindowsHandleInfo whi = new WindowsHandleInfo())
            {
                for (int i = 0; i < whi.HandleCount; i++)
                {
                    var she = whi[i];

                    if (she.OwnerPid != processId)
                    {
                        continue;
                    }

                    string objName = she.GetName(out string handleTypeName);
                    if (handleTypeName == "Thread")
                    {
                        return she.ObjectPointer;
                    }
                }
            }

            return IntPtr.Zero;
        }
    }
}
