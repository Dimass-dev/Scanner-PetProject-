using Core.Models;
using Core.PE;
using Core.Sections;
using Xunit;

namespace Scanner.Tests
{
    public class SectionParserTests
    {
        private const string TestFilePath = @"C:\Windows\System32\notepad.exe";

        [Fact]
        public void Parse_ValidPEFile_ReturnsSuccessAndSections()
        {
            var headerParser = new HeaderParser();
            var headerResult = headerParser.Parse(TestFilePath);
            
            Assert.True(headerResult.IsSuccess);
            Assert.NotNull(headerResult.Info);

            var sectionParser = new SectionParser();
            var sectionResult = sectionParser.Parse(TestFilePath, headerResult.Info);

            Assert.True(sectionResult.IsSuccess);
            Assert.Null(sectionResult.ErrorMessage);
            Assert.NotNull(sectionResult.SectionInfo);
            Assert.True(sectionResult.SectionInfo.Count > 0);

            Assert.Contains(sectionResult.SectionInfo, s => s.SectionName == ".text");
            
            var textSection = sectionResult.SectionInfo.Find(s => s.SectionName == ".text");
            Assert.NotNull(textSection);
            Assert.True(textSection.Characteristics.HasFlag(SectionFlag.MemExecute));
        }

        [Fact]
        public void Parse_InvalidFilePath_ReturnsFail()
        {
            string invalidFilePath = @"C:\NonExistent_Fake_File.exe";
            var sectionParser = new SectionParser();
            
            var dummyInfo = new HPInfo 
            { 
                NumberOfSections = 1, 
                SectionOffset = 512 
            };

            var sectionResult = sectionParser.Parse(invalidFilePath, dummyInfo);

            Assert.False(sectionResult.IsSuccess);
            Assert.NotNull(sectionResult.ErrorMessage);
            Assert.Null(sectionResult.SectionInfo);
            Assert.Contains("File not found", sectionResult.ErrorMessage);
        }
    }
}