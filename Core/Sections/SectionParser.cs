namespace Core.Sections;
using Core.Models;
using Core.PE;
using System.Collections.Generic;
using System.IO;
public class SectionParser
{
    public SingleSectionResult Parse(string filePath, HPInfo info)
    {
        if (!File.Exists(filePath)) return SingleSectionResult.Fail("File not found");
        var sections = new List<SingleSectionInfo>();
        using var file = new FileStream(filePath, FileMode.Open,FileAccess.Read);
        file.Seek(info.SectionOffset, SeekOrigin.Begin);
        int bytesToRead = (int)(info.NumberOfSections * 40);
        byte[] buffer = new byte[bytesToRead];
        file.ReadExactly(buffer, 0, buffer.Length);
        ReadOnlySpan<byte> sectionSpan = buffer;
        for(int i = 0; i < info.NumberOfSections; i++)
        {
            int sectionStart = i * 40;
            var sectionInfo = new SingleSectionInfo
            {
                SectionName = System.Text.Encoding.UTF8.GetString(sectionSpan.Slice(sectionStart, 8)).TrimEnd('\0'),
                VirtualSize = BitConverter.ToUInt32(sectionSpan.Slice(sectionStart + 8, 4)),
                VirtualAddress = BitConverter.ToUInt32(sectionSpan.Slice(sectionStart + 12, 4)),
                SizeOfRawData = BitConverter.ToUInt32(sectionSpan.Slice(sectionStart + 16, 4)),
                PointerToRawData = BitConverter.ToUInt32(sectionSpan.Slice(sectionStart + 20, 4)),
                Characteristics = (SectionFlag)BitConverter.ToUInt32(sectionSpan.Slice(sectionStart + 36, 4))
            };
            sections.Add(sectionInfo);
        }
        return SingleSectionResult.Success(sections); 
    }
}