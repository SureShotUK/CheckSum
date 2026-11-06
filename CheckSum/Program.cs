using CheckSum;

// Usage:
//   CheckSum                      interactive loop (prompts for file path and checksum)
//   CheckSum <file> <checksum>    one-off check; exit code 0 = match, 1 = no match, 2 = error

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    // Only intercept Ctrl+C while hashing; at an idle prompt let the default behaviour end the app.
    if (HashingState.Active)
    {
        e.Cancel = true;
        cts.Cancel();
    }
};

bool interactive = args.Length == 0;
int exitCode = 2;

try
{
    if (args.Length == 2)
    {
        exitCode = await CheckOneAsync(args[0], args[1], cts.Token);
    }
    else if (args.Length == 0)
    {
        exitCode = await RunInteractiveAsync(cts.Token);
    }
    else
    {
        Console.Error.WriteLine("Usage: CheckSum [<file> <checksum>]");
    }
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Cancelled.");
    exitCode = 2;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"ERROR: Could not read the file: {ex.Message}");
    exitCode = 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Fatal error: {ex.Message}");
    exitCode = 2;
}

if (interactive && !Console.IsInputRedirected)
{
    Console.WriteLine();
    Console.Write("Press Enter to exit...");
    Console.ReadLine();
}

return exitCode;

static async Task<int> RunInteractiveAsync(CancellationToken ct)
{
    Console.WriteLine("Checksum verifier — checks a file against CRC32, MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512.");
    Console.WriteLine("Leave the file path empty to quit.");

    while (!ct.IsCancellationRequested)
    {
        Console.WriteLine();
        Console.Write("File path: ");
        string? path = ChecksumInput.CleanPath(Console.ReadLine()); // null on blank or end of input => quit
        if (path is null)
        {
            break;
        }

        Console.Write("Checksum : ");
        string? checksum = Console.ReadLine();
        if (checksum is null)
        {
            break;
        }

        try
        {
            await CheckOneAsync(path, checksum, ct);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Cancelled.");
            break;
        }
        catch (Exception ex)
        {
            // One bad file must not end the session.
            Console.WriteLine($"ERROR: {ex.Message}");
        }
    }

    return 0;
}

static async Task<int> CheckOneAsync(string rawPath, string rawChecksum, CancellationToken ct)
{
    string? path = ChecksumInput.CleanPath(rawPath);
    if (path is null)
    {
        Console.WriteLine("ERROR: No file path entered.");
        return 2;
    }

    string? expected = ChecksumInput.CleanChecksum(rawChecksum, out string? inputError);
    if (expected is null)
    {
        Console.WriteLine($"ERROR: {inputError}");
        return 2;
    }

    if (Directory.Exists(path))
    {
        Console.WriteLine("ERROR: That path is a folder, not a file.");
        return 2;
    }

    if (!File.Exists(path))
    {
        Console.WriteLine($"ERROR: File not found: {path}");
        return 2;
    }

    var candidates = ChecksumVerifier.CandidatesFor(expected.Length);
    if (candidates.Count == 0)
    {
        Console.WriteLine(
            $"ERROR: A {expected.Length}-character checksum doesn't match any supported algorithm " +
            $"(supported lengths: {string.Join(", ", ChecksumVerifier.SupportedHexLengths)}).");
        return 2;
    }

    Console.WriteLine($"Checking against: {string.Join(", ", candidates)}");

    // Synchronous reporter (not Progress<T>, which posts to the thread pool and can write after the result).
    var progress = Console.IsOutputRedirected ? null : new SyncProgress<(long Read, long Total)>(p =>
    {
        if (p.Total > 0)
        {
            Console.Write($"\r  {p.Read * 100 / p.Total,3}%");
        }
    });

    VerificationResult result;
    HashingState.Active = true;
    try
    {
        result = await ChecksumVerifier.VerifyAsync(path, expected, progress, ct);
    }
    finally
    {
        HashingState.Active = false;
    }

    if (progress is not null)
    {
        Console.Write("\r      \r");
    }

    if (result.Matches.Count > 0)
    {
        Console.WriteLine($"MATCH: {string.Join(", ", result.Matches)}");
        return 0;
    }

    Console.WriteLine("NO MATCH. The file does not match the checksum you entered.");
    foreach (var (name, hex) in result.Computed)
    {
        Console.WriteLine($"  {name,-9} computed: {hex}");
    }

    Console.WriteLine($"  {"Expected",-9}          : {expected}");
    return 1;
}

internal static class HashingState
{
    public static volatile bool Active;
}

internal sealed class SyncProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}
