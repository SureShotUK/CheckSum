using CheckSum;

namespace CheckSum.Tests;

public sealed class ChecksumTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("checksum-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteFile(string content)
    {
        string path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, content);
        return path;
    }

    // Digests of the ASCII string "abc".
    private const string Md5 = "900150983cd24fb0d6963f7d28e17f72";
    private const string Sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
    private const string Sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string Crc32 = "352441c2";

    [Theory]
    [InlineData(Md5, "MD5")]
    [InlineData(Sha1, "SHA-1")]
    [InlineData(Sha256, "SHA-256")]
    [InlineData(Crc32, "CRC32")]
    public async Task Matching_checksum_reports_algorithm(string hex, string algorithm)
    {
        var result = await ChecksumVerifier.VerifyAsync(WriteFile("abc"), hex);
        Assert.Contains(algorithm, result.Matches);
    }

    [Fact]
    public async Task Uppercase_expected_hex_is_matched_after_cleaning()
    {
        string? cleaned = ChecksumInput.CleanChecksum(Sha256.ToUpperInvariant(), out _);
        var result = await ChecksumVerifier.VerifyAsync(WriteFile("abc"), cleaned!);
        Assert.Contains("SHA-256", result.Matches);
    }

    [Fact]
    public async Task Wrong_checksum_of_valid_length_gives_no_match()
    {
        var result = await ChecksumVerifier.VerifyAsync(WriteFile("abd"), Sha256);
        Assert.Empty(result.Matches);
        Assert.NotEmpty(result.Computed);
    }

    [Fact]
    public async Task Unsupported_length_throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => ChecksumVerifier.VerifyAsync(WriteFile("abc"), "abcd"));
    }

    [Fact]
    public async Task Empty_file_hashes_correctly()
    {
        var result = await ChecksumVerifier.VerifyAsync(WriteFile(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        Assert.Contains("SHA-256", result.Matches);
    }

    [Fact]
    public async Task File_larger_than_buffer_hashes_correctly()
    {
        string path = Path.Combine(_dir, "big.bin");
        byte[] data = new byte[3 * 1024 * 1024 + 17];
        new Random(42).NextBytes(data);
        File.WriteAllBytes(path, data);

        string expected = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(data));
        var result = await ChecksumVerifier.VerifyAsync(path, expected);
        Assert.Contains("SHA-256", result.Matches);
    }

    [Fact]
    public async Task Cancellation_is_honoured()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChecksumVerifier.VerifyAsync(WriteFile("abc"), Sha256, null, cts.Token));
    }

    [Theory]
    [InlineData("  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  ")]
    [InlineData("sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [InlineData("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad *abc.txt")]
    [InlineData("\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"")]
    public void CleanChecksum_accepts_common_pasted_forms(string raw)
    {
        Assert.Equal(Sha256, ChecksumInput.CleanChecksum(raw, out string? error));
        Assert.Null(error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("xyz123")]
    [InlineData(null)]
    public void CleanChecksum_rejects_bad_input(string? raw)
    {
        Assert.Null(ChecksumInput.CleanChecksum(raw, out string? error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("\"C:\\a b\\file.iso\"", "C:\\a b\\file.iso")]
    [InlineData("  C:\\file.iso ", "C:\\file.iso")]
    [InlineData("", null)]
    [InlineData("\"\"", null)]
    public void CleanPath_strips_quotes_and_blanks(string raw, string? expected)
    {
        Assert.Equal(expected, ChecksumInput.CleanPath(raw));
    }

    [Fact]
    public void Candidates_by_length()
    {
        Assert.Equal(["CRC32"], ChecksumVerifier.CandidatesFor(8));
        Assert.Contains("SHA-256", ChecksumVerifier.CandidatesFor(64));
        Assert.Empty(ChecksumVerifier.CandidatesFor(7));
    }
}
