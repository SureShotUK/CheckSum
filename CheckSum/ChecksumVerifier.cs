using System.Globalization;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace CheckSum;

/// <summary>Result of checking one file against one expected checksum.</summary>
/// <param name="Matches">Names of the algorithms whose digest equals the expected checksum.</param>
/// <param name="Computed">Every digest that was computed (algorithm name to lower-case hex).</param>
public sealed record VerificationResult(IReadOnlyList<string> Matches, IReadOnlyDictionary<string, string> Computed);

/// <summary>Computes candidate digests of a file in a single pass and compares them to an expected checksum.</summary>
public static class ChecksumVerifier
{
    private sealed record Algorithm(string Name, int HexLength, Func<IDigest> Create, bool IsSupported);

    // Tiny abstraction so cryptographic and non-cryptographic algorithms share one read loop.
    private interface IDigest : IDisposable
    {
        void Append(ReadOnlySpan<byte> data);
        string FinishHex();
    }

    private sealed class CryptoDigest(HashAlgorithmName name) : IDigest
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(name);
        public void Append(ReadOnlySpan<byte> data) => _hash.AppendData(data);
        public string FinishHex() => Convert.ToHexStringLower(_hash.GetHashAndReset());
        public void Dispose() => _hash.Dispose();
    }

    private sealed class Crc32Digest : IDigest
    {
        private readonly Crc32 _crc = new();
        public void Append(ReadOnlySpan<byte> data) => _crc.Append(data);

        // Conventional CRC-32 display is the big-endian hex of the 32-bit value.
        public string FinishHex() => _crc.GetCurrentHashAsUInt32().ToString("x8", CultureInfo.InvariantCulture);
        public void Dispose() { }
    }

    private static readonly Algorithm[] All =
    [
        new("CRC32",    8,   () => new Crc32Digest(), true),
        new("MD5",      32,  () => new CryptoDigest(HashAlgorithmName.MD5), true),
        new("SHA-1",    40,  () => new CryptoDigest(HashAlgorithmName.SHA1), true),
        new("SHA-256",  64,  () => new CryptoDigest(HashAlgorithmName.SHA256), true),
        new("SHA3-256", 64,  () => new CryptoDigest(HashAlgorithmName.SHA3_256), SHA3_256.IsSupported),
        new("SHA-384",  96,  () => new CryptoDigest(HashAlgorithmName.SHA384), true),
        new("SHA-512",  128, () => new CryptoDigest(HashAlgorithmName.SHA512), true),
        new("SHA3-512", 128, () => new CryptoDigest(HashAlgorithmName.SHA3_512), SHA3_512.IsSupported),
    ];

    private const int BufferSize = 1024 * 1024;

    /// <summary>Distinct hex lengths we can verify, for error messages.</summary>
    public static IReadOnlyList<int> SupportedHexLengths { get; } =
        All.Where(a => a.IsSupported).Select(a => a.HexLength).Distinct().Order().ToArray();

    /// <summary>Names of the algorithms that apply to a checksum of this many hex characters.</summary>
    public static IReadOnlyList<string> CandidatesFor(int hexLength) =>
        All.Where(a => a.IsSupported && a.HexLength == hexLength).Select(a => a.Name).ToArray();

    /// <summary>
    /// Hashes <paramref name="path"/> once with every algorithm whose digest length equals the length of
    /// <paramref name="expectedHex"/> (lower-case hex) and reports which of them match.
    /// </summary>
    /// <exception cref="ArgumentException">No supported algorithm produces a digest of that length.</exception>
    public static async Task<VerificationResult> VerifyAsync(
        string path,
        string expectedHex,
        IProgress<(long Read, long Total)>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var candidates = All.Where(a => a.IsSupported && a.HexLength == expectedHex.Length).ToArray();
        if (candidates.Length == 0)
        {
            throw new ArgumentException(
                $"No supported algorithm produces a {expectedHex.Length}-character checksum. " +
                $"Supported lengths: {string.Join(", ", SupportedHexLengths)}.",
                nameof(expectedHex));
        }

        var digests = new List<(Algorithm Algorithm, IDigest Digest)>(candidates.Length);
        try
        {
            foreach (var candidate in candidates)
            {
                digests.Add((candidate, candidate.Create()));
            }

            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, BufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);

            long total = stream.Length;
            long read = 0;
            byte[] buffer = new byte[BufferSize];
            int count;
            while ((count = await stream.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
            {
                foreach (var (_, digest) in digests)
                {
                    digest.Append(buffer.AsSpan(0, count));
                }

                read += count;
                progress?.Report((read, total));
            }

            var computed = new Dictionary<string, string>(digests.Count);
            var matches = new List<string>();
            foreach (var (algorithm, digest) in digests)
            {
                string hex = digest.FinishHex();
                computed[algorithm.Name] = hex;
                if (string.Equals(hex, expectedHex, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(algorithm.Name);
                }
            }

            return new VerificationResult(matches, computed);
        }
        finally
        {
            foreach (var (_, digest) in digests)
            {
                digest.Dispose();
            }
        }
    }
}
