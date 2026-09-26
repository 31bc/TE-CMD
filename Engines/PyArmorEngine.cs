using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Engines;

static class PyArmorEngine
{
    public static async Task ExtractAsync(string exePath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        log($"[PyArmor] Analyzing {Path.GetFileName(exePath)} ...");
        var data = await File.ReadAllBytesAsync(exePath);
        var txt = Encoding.ASCII.GetString(data);
        bool isPyArmor = txt.Contains("pyarmor") || txt.ToLower().Contains("pyarmor")
            || txt.Contains("pytransform") || txt.Contains("pyarmor_runtime");
        string version = DetectVersion(txt);
        log($"[PyArmor] Detected: {isPyArmor} Version: {version}");

        // Step 1: Run the static unpacker
            string? unpackerScript = FindUnpackerScript();
        if (unpackerScript != null)
        {
            log($"[PyArmor] Running static unpacker: {Path.GetFileName(unpackerScript)}");
            string unpackOut = Path.Combine(outDir, "pyarmor_extracted");
            Directory.CreateDirectory(unpackOut);

            var psi = new ProcessStartInfo("python", $" \"{unpackerScript}\" \"{exePath}\" \"{unpackOut}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.Environment["PYTHONUTF8"] = "1";

            using var p = Process.Start(psi);
            if (p != null)
            {
                var stdoutLines = new List<string>();
                p.OutputDataReceived += (s, e) => { if (e.Data != null) stdoutLines.Add(e.Data); };
                p.ErrorDataReceived += (s, e) => { if (e.Data != null && !e.Data.Contains("Warning")) stdoutLines.Add("[err] " + e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit(120000); // 2 min timeout

                foreach (var l in stdoutLines.TakeLast(40))
                    if (!string.IsNullOrWhiteSpace(l)) log("  " + l.Trim());

                int extractedCount = Directory.GetFiles(unpackOut, "*", SearchOption.AllDirectories).Length;
                log($"[PyArmor] Static unpacker: {extractedCount} files extracted");

                // Copy extracted files to output
                if (extractedCount > 0)
                {
                    foreach (var f in Directory.GetFiles(unpackOut, "*", SearchOption.AllDirectories))
                    {
                        string rel = Path.GetRelativePath(unpackOut, f);
                        string dst = Path.Combine(outDir, rel);
                        Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                        File.Copy(f, dst, true);
                    }
                }
            }
        }
        else
        {
            log("[PyArmor] Static unpacker not found - using built-in methods");
        }

        // Step 2: Built-in .pyc scanning
        log("[PyArmor] Scanning for .pyc signatures...");
        int pycCount = ScanAndExtractPyc(data, outDir, log);
        log($"[PyArmor] Found {pycCount} .pyc signatures");

        // Step 3: String extraction
        var strings = ExtractStrings(data);
        await File.WriteAllTextAsync(Path.Combine(outDir, "pyarmor_strings.txt"),
            string.Join("\n", strings.Take(2000)), Encoding.UTF8);
        log($"[PyArmor] strings.txt: {strings.Count} strings");

        // Step 4: Try brute force XOR
        log("[PyArmor] Trying XOR decryption on data sections...");
        int xorCount = TryXorDecrypt(data, outDir, log);
        log($"[PyArmor] XOR: {xorCount} potential decrypts");

        // Step 5: Write guide
        await WriteGuide(exePath, outDir, version, log);

        int totalFiles = Directory.GetFiles(outDir, "*", SearchOption.AllDirectories).Length;
        log($"[PyArmor] Total output: {totalFiles} files");
    }

    static string DetectVersion(string txt)
    {
        if (txt.Contains("pyarmor-v8") || txt.Contains("v8")) return "v8+";
        if (txt.Contains("pyarmor") && (txt.Contains("3.9") || txt.Contains("3.10") || txt.Contains("3.11") || txt.Contains("3.12"))) return "v7+";
        if (txt.Contains("pyarmor")) return "v5-v7";
        return "Unknown";
    }

    static string? FindUnpackerScript()
    {
        string[] cands = new[]{
            Path.Combine(AppContext.BaseDirectory,"Assets","pyarmor-unpacker","pyarmor_unpacker.py"),
            Path.Combine(Directory.GetCurrentDirectory(),"Assets","pyarmor-unpacker","pyarmor_unpacker.py"),
        };
        return cands.FirstOrDefault(File.Exists);
    }

    static int ScanAndExtractPyc(byte[] data, string outDir, Action<string> log)
    {
        // Python magic numbers
        byte[][] magics = new byte[][] {
            new byte[]{0x42,0x0d,0x0d,0x0a}, // 3.7
            new byte[]{0x55,0x0d,0x0d,0x0a}, // 3.8
            new byte[]{0x61,0x0d,0x0d,0x0a}, // 3.9
            new byte[]{0x6f,0x0d,0x0d,0x0a}, // 3.10
            new byte[]{0xa7,0x0d,0x0d,0x0a}, // 3.11
            new byte[]{0x33,0x0d,0x0d,0x0a}, // 3.12
            new byte[]{0xf3,0x0d,0x0d,0x0a}, // 3.13
        };

        int count = 0;
        string pycDir = Path.Combine(outDir, "pyc_extracted");
        Directory.CreateDirectory(pycDir);

        foreach (var magic in magics)
        {
            int pos = 0;
            while (true)
            {
                int idx = FindBytes(data, magic, pos);
                if (idx < 0) break;

                // Validate: timestamp + size after magic
                if (idx + 12 <= data.Length)
                {
                    uint ts = BitConverter.ToUInt32(data, idx + 4);
                    uint sz = BitConverter.ToUInt32(data, idx + 8);
                    if (sz < 10000000) // < 10MB
                    {
                        int len = (int)Math.Min(sz + 16, data.Length - idx);
                        byte[] pycData = new byte[len];
                        Array.Copy(data, idx, pycData, 0, len);

                        string name = $"pyc_{idx:X6}_{magic[0]:X2}{magic[1]:X2}.pyc";
                        File.WriteAllBytes(Path.Combine(pycDir, name), pycData);
                        count++;
                        log($"  [+] {name} at 0x{idx:X}");
                    }
                }
                pos = idx + 1;
            }
        }

        // Copy to main output
        if (count > 0)
        {
            foreach (var f in Directory.GetFiles(pycDir))
                File.Copy(f, Path.Combine(outDir, Path.GetFileName(f)), true);
        }

        return count;
    }

    static int FindBytes(byte[] haystack, byte[] needle, int start)
    {
        for (int i = start; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    static int TryXorDecrypt(byte[] data, string outDir, Action<string> log)
    {
        byte[][] keys = new byte[][] {
            Encoding.UTF8.GetBytes("pyarmor"),
            Encoding.UTF8.GetBytes("pytransform"),
            new byte[]{0x42,0x55,0xAA,0x55},
            new byte[]{0x66,0x66,0x66,0x66},
            new byte[]{0x12,0x34,0x56,0x78},
        };

        int count = 0;
        int scanLen = Math.Min(100000, data.Length);
        byte[] sample = new byte[scanLen];
        Array.Copy(data, Math.Min(0x1000, data.Length), sample, 0, scanLen);

        foreach (var key in keys)
        {
            byte[] decrypted = new byte[scanLen];
            for (int i = 0; i < scanLen; i++)
                decrypted[i] = (byte)(sample[i] ^ key[i % key.Length]);

            // Check if looks like Python
            int printable = 0;
            int pyHints = 0;
            for (int i = 0; i < Math.Min(1000, decrypted.Length); i++)
            {
                if (decrypted[i] >= 32 && decrypted[i] <= 126) printable++;
                if (i + 6 < decrypted.Length)
                {
                    string s = Encoding.ASCII.GetString(decrypted, i, 6);
                    if (s == "import" || s == "def " || s == "class ") pyHints++;
                }
            }

            if (pyHints > 0)
            {
                log($"  [+] Key {Convert.ToHexString(key[..4])} produced {pyHints} Python hints");
                // Full decrypt
                byte[] fullDec = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                    fullDec[i] = (byte)(data[i] ^ key[i % key.Length]);

                // Find .pyc in decrypted
                byte[][] magics = new byte[][] {
                    new byte[]{0x42,0x0d,0x0d,0x0a}, new byte[]{0x55,0x0d,0x0d,0x0a},
                    new byte[]{0x61,0x0d,0x0d,0x0a}, new byte[]{0x6f,0x0d,0x0d,0x0a},
                };
                foreach (var magic in magics)
                {
                    int idx = FindBytes(fullDec, magic, 0);
                    if (idx >= 0 && idx < fullDec.Length - 16)
                    {
                        int len = Math.Min(100000, fullDec.Length - idx);
                        File.WriteAllBytes(Path.Combine(outDir, $"xor_{idx:X6}.pyc"), fullDec[idx..(idx+len)]);
                        count++;
                        log($"  [+] xor_{idx:X6}.pyc extracted");
                    }
                }
                if (count > 0) break;
            }
        }
        return count;
    }

    static List<string> ExtractStrings(byte[] data)
    {
        var sb = new StringBuilder();
        var res = new List<string>();
        foreach (var b in data)
        {
            if (b >= 32 && b <= 126) sb.Append((char)b);
            else
            {
                if (sb.Length > 6) res.Add(sb.ToString());
                sb.Clear();
            }
        }
        return res.Distinct().Where(s => s.Length > 7 && s.Length < 300).ToList();
    }

    static async Task WriteGuide(string exePath, string outDir, string version, Action<string> log)
    {
        string pyDll = DetectPythonVersion(exePath);
        string guide = $@"
PyArmor Unpacker Results
========================
Input: {Path.GetFileName(exePath)}
PyArmor Version: {version}
Python: {pyDll}

Extraction Methods:
  1. Static unpacker (pyarmor_unpacker.py)
  2. .pyc header scan (magic bytes)
  3. XOR brute force (common keys)
  4. String extraction

Next Steps:
  1. Check extracted .pyc files
  2. Decompile with: pycdc, pylingual.io, or uncompyle6
  3. For v8+: Use dynamic method
     - Copy method_1/ or method_3/ to target folder
     - Run target, inject with Process Hacker
     - Or use Frida: frida -U -f target.exe

Files:
  - pyc_extracted/    - Raw .pyc files
  - pyarmor_strings.txt - Extracted strings
  - REPORT.txt        - Full report
";
        await File.WriteAllTextAsync(Path.Combine(outDir, "README.txt"), guide, Encoding.UTF8);
        log($"[PyArmor] README.txt written");
    }

    static string DetectPythonVersion(string exePath)
    {
        try
        {
            var data = File.ReadAllBytes(exePath);
            var txt = Encoding.ASCII.GetString(data);
            var match = Regex.Match(txt, @"python3(\d+)\.dll");
            if (match.Success) return $"Python 3.{match.Groups[1].Value}";
            // Check magic numbers
            if (txt.Contains("3.14")) return "Python 3.14";
            if (txt.Contains("3.13")) return "Python 3.13";
            if (txt.Contains("3.12")) return "Python 3.12";
            if (txt.Contains("3.11")) return "Python 3.11";
            if (txt.Contains("3.10")) return "Python 3.10";
            if (txt.Contains("3.9")) return "Python 3.9";
        }
        catch { }
        return "Unknown";
    }
}
