using Core.PE;
using Core.Sections;
using System;
using System.IO;

namespace Scanner.ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            string filePath = @"C:\Windows\System32\notepad.exe";

            Console.WriteLine("============================================================");
            Console.WriteLine($"[+] SCANNING FILE: {Path.GetFileName(filePath)}");
            Console.WriteLine("============================================================\n");

            // --- STAGE 1: Parse Base Headers ---
            Console.WriteLine("[*] Reading DOS and PE headers...");
            var headerParser = new HeaderParser();
            var headerResult = headerParser.Parse(filePath);

            if (!headerResult.IsSuccess)
            {
                Console.WriteLine($"[-] ERROR: {headerResult.ErrorMessage}");
                return;
            }

            var info = headerResult.Info;
            Console.WriteLine("[+] Base headers parsed successfully!\n");

            Console.WriteLine("--- BASIC FILE INFORMATION ---");
            Console.WriteLine($"PE Header Offset:        0x{info!.PeOffset:X4}");
            Console.WriteLine($"Architecture (Machine):  {info.Architecture}");
            Console.WriteLine($"Optional Header Size:    {info.SizeOfOptionalHeader} bytes");
            Console.WriteLine($"Number of Sections:      {info.NumberOfSections}");
            Console.WriteLine($"Section Table Offset:    0x{info.SectionOffset:X4}");

            Console.WriteLine("\n--- SECURITY MECHANISMS ---");
            Console.WriteLine($"ASLR Enabled:            {(info.HasASLR ? "Yes" : "No")}");
            Console.WriteLine($"DEP (NX Bit) Enabled:    {(info.HasDEP ? "Yes" : "No")}");
            Console.WriteLine();

            // --- STAGE 2: Parse Section Table ---
            Console.WriteLine("[*] Reading Section Table...");
            var sectionParser = new SectionParser();
            var sectionResult = sectionParser.Parse(filePath, info);

            if (!sectionResult.IsSuccess)
            {
                Console.WriteLine($"[-] ERROR READING SECTIONS: {sectionResult.ErrorMessage}");
                return;
            }

            Console.WriteLine("[+] Section Table parsed successfully!\n");

            Console.WriteLine($"{"Name",-8} | {"V. Size",-10} | {"V. Address",-10} | {"Raw Size",-10} | {"Raw Ptr",-10} | {"Flags",-45}");
            Console.WriteLine(new string('-', 110));
            foreach (var sec in sectionResult.SectionInfo!)
            {
                Console.WriteLine($"{sec.SectionName,-8} | 0x{sec.VirtualSize:X8} | 0x{sec.VirtualAddress:X8} | 0x{sec.SizeOfRawData:X8} | 0x{sec.PointerToRawData:X8} | {sec.Characteristics}");
            }

            Console.WriteLine("\n============================================================");
            Console.WriteLine("[+] SCAN COMPLETE");
            Console.WriteLine("============================================================");
        }
    }
}