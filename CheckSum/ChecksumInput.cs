using System.Globalization;

namespace CheckSum;

/// <summary>Cleans up what the user types or pastes for the file path and the checksum.</summary>
public static class ChecksumInput
{
    /// <summary>
    /// Removes surrounding quotes (added by drag-and-drop / "Copy as path") and whitespace.
    /// Returns null for blank input.
    /// </summary>
    public static string? CleanPath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        string path = raw.Trim();
        if (path.Length >= 2 && path[0] == '"' && path[^1] == '"')
        {
            path = path[1..^1].Trim();
        }

        return path.Length == 0 ? null : path;
    }

    /// <summary>
    /// Extracts a hex checksum from user input. Accepts a bare hash, "algo:hash", a "0x" prefix,
    /// or a whole line from a checksum file ("hash  filename" / "hash *filename").
    /// Returns the lower-cased hex string, or null (with <paramref name="error"/> set) if invalid.
    /// </summary>
    public static string? CleanChecksum(string? raw, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "No checksum entered.";
            return null;
        }

        // Only the first token matters: the rest of a checksum-file line is the file name.
        string token = raw.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];

        int colon = token.IndexOf(':');
        if (colon >= 0)
        {
            token = token[(colon + 1)..];
        }

        token = token.Trim('"', '\'');
        if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            token = token[2..];
        }

        if (token.Length == 0)
        {
            error = "No checksum entered.";
            return null;
        }

        foreach (char c in token)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                error = "The checksum must contain only hexadecimal characters (0-9, a-f).";
                return null;
            }
        }

        return token.ToLower(CultureInfo.InvariantCulture);
    }
}
