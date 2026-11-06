# CheckSum

.NET 10 console app: enter a file path and a checksum; the file is hashed once with every
algorithm whose digest length matches (CRC32, MD5, SHA-1, SHA-256, SHA3-256, SHA-384,
SHA-512, SHA3-512) and the matching algorithm(s) are reported.

- `CheckSum/` — console app (`Program.cs` UI, `ChecksumInput.cs` input cleanup, `ChecksumVerifier.cs` hashing)
- `CheckSum.Tests/` — xUnit tests
- Run: `dotnet run --project CheckSum` (interactive) or `... -- <file> <checksum>` (exit 0 match, 1 no match, 2 error)
- SHA3 is gated on `IsSupported` (needs OpenSSL 1.1.1+/Windows 11 style platform support).
