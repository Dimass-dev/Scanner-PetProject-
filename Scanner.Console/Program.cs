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
            // Можешь поменять этот путь на любой свой .exe или .dll
            string filePath = @"C:\Windows\System32\notepad.exe";

            Console.WriteLine("============================================================");
            Console.WriteLine($"[+] ЗАПУСК СКАНИРОВАНИЯ: {Path.GetFileName(filePath)}");
            Console.WriteLine("============================================================\n");

            // --- ЭТАП 1: Анализ базовых заголовков ---
            Console.WriteLine("[*] Чтение DOS и PE заголовков...");
            var headerParser = new HeaderParser();
            var headerResult = headerParser.Parse(filePath);

            if (!headerResult.IsSuccess)
            {
                Console.WriteLine($"[-] ОШИБКА: {headerResult.ErrorMessage}");
                return;
            }

            var info = headerResult.Info;
            Console.WriteLine("[+] Базовые заголовки успешно проанализированы!\n");
            
            Console.WriteLine("--- ОСНОВНАЯ ИНФОРМАЦИЯ О ФАЙЛЕ ---");
            Console.WriteLine($"Смещение PE заголовка:    0x{info!.PeOffset:X4}");
            Console.WriteLine($"Архитектура (Machine):    {info.Architecture}");
            Console.WriteLine($"Размер OptionalHeader:    {info.SizeOfOptionalHeader} байт");
            Console.WriteLine($"Количество секций:        {info.NumberOfSections}");
            Console.WriteLine($"Начало таблицы секций:    0x{info.SectionOffset:X4}");
            
            Console.WriteLine("\n--- МЕХАНИЗМЫ БЕЗОПАСНОСТИ ---");
            Console.WriteLine($"Поддержка ASLR:           {(info.HasASLR ? "Да" : "Нет")}");
            Console.WriteLine($"Поддержка DEP (NX Bit):   {(info.HasDEP ? "Да" : "Нет")}");
            Console.WriteLine();

            // --- ЭТАП 2: Анализ секций ---
            Console.WriteLine("[*] Чтение таблицы секций...");
            var sectionParser = new SectionParser();
            var sectionResult = sectionParser.Parse(filePath, info);

            if (!sectionResult.IsSuccess)
            {
                Console.WriteLine($"[-] ОШИБКА ПРИ ЧТЕНИИ СЕКЦИЙ: {sectionResult.ErrorMessage}");
                return;
            }

            Console.WriteLine("[+] Таблица секций успешно прочитана!\n");

            // Красивая шапка таблицы (добавили колонку Characteristics)
            Console.WriteLine($"{"Имя",-8} | {"V. Size",-10} | {"V. Address",-10} | {"Raw Size",-10} | {"Raw Ptr",-10} | {"Flags",-10}");
            Console.WriteLine(new string('-', 75));

            // Вывод всех секций
            foreach (var sec in sectionResult.SectionInfo!)
            {
                Console.WriteLine($"{sec.SectionName,-8} | 0x{sec.VirtualSize:X8} | 0x{sec.VirtualAddress:X8} | 0x{sec.SizeOfRawData:X8} | 0x{sec.PointerToRawData:X8} | 0x{sec.Characteristics:X8}");
            }

            Console.WriteLine("\n============================================================");
            Console.WriteLine("[+] СКАНИРОВАНИЕ ЗАВЕРШЕНО");
            Console.WriteLine("============================================================");
        }
    }
}