using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Engines;

static class CppEngine
{
    public static async Task AnalyzeAsync(string exePath, string outDir, Action<string> log)
    {
        Directory.CreateDirectory(outDir);
        log($"[C++ KILLER] Analyzing {Path.GetFileName(exePath)} ...");
        var data = await File.ReadAllBytesAsync(exePath);
        long origSize = data.Length;

        string info = BuildReport(exePath, data, log);
        await File.WriteAllTextAsync(Path.Combine(outDir, "pe_report.txt"), info, Encoding.UTF8);
        log(info);

        string sections = Helpers.PeHelper.GetSectionsInfo(exePath);
        await File.WriteAllTextAsync(Path.Combine(outDir, "sections.txt"), sections, Encoding.UTF8);
        log(sections);

        var strings = ExtractStrings(data, log);
        await File.WriteAllTextAsync(Path.Combine(outDir, "strings.txt"), string.Join("\n", strings), Encoding.UTF8);
        log($"[Killer] Strings: {strings.Count} (filtered, deobfuscated)");

        var imports = ExtractImports(data);
        await File.WriteAllTextAsync(Path.Combine(outDir, "imports.txt"), string.Join("\n", imports), Encoding.UTF8);
        log($"[Killer] Imports: {string.Join(", ", imports.Take(10))}");

        string hex = BuildHexDump(data);
        await File.WriteAllTextAsync(Path.Combine(outDir, "hexdump.txt"), hex, Encoding.UTF8);

        string compiler = DetectCompiler(data);
        await File.WriteAllTextAsync(Path.Combine(outDir, "compiler.txt"), compiler, Encoding.UTF8);
        log($"[Killer] Compiler: {compiler}");

        string protection = Helpers.PeHelper.DetectProtection(exePath);
        await File.WriteAllTextAsync(Path.Combine(outDir, "protection.txt"), protection, Encoding.UTF8);
        log(protection);

        string yara = RunYara(data, log);
        await File.WriteAllTextAsync(Path.Combine(outDir, "yara.txt"), yara, Encoding.UTF8);
        log(yara);

        string capstone = await TryCapstone(exePath, outDir, log);
        string entropy = AnalyzeEntropy(data, log);
        await File.WriteAllTextAsync(Path.Combine(outDir, "entropy.txt"), entropy, Encoding.UTF8);
        log(entropy);

        string anti = DetectAnti(data, log);
        await File.WriteAllTextAsync(Path.Combine(outDir, "anti.txt"), anti, Encoding.UTF8);
        log(anti);

        // Smart validation: if file is actually .NET or Python but misdetected as C++, warn
        if (Helpers.Detector.Detect(exePath) != Helpers.PackerType.Cpp)
            log($"[Smart] Warning: file detected as {Helpers.Detector.Describe(Helpers.Detector.Detect(exePath))} but analyzed as C++ - may be packed");

        log("✅ [KILLER] C++ analysis completed - for full decompilation use Ghidra/IDA/x64dbg + capstone.txt");
        log($"[Killer] Output: pe_report.txt, sections.txt, strings.txt ({strings.Count}), imports.txt, hexdump.txt, compiler.txt, protection.txt, yara.txt, capstone.asm, entropy.txt, anti.txt");
        log($"[Killer] Total output size: {Directory.GetFiles(outDir,"*",SearchOption.AllDirectories).Sum(f=>new FileInfo(f).Length)/1024} KB vs original {origSize/1024} KB");
    }

    static string BuildReport(string path, byte[] d, Action<string> log)
    {
        var sb=new StringBuilder();
        sb.AppendLine($"File: {path}");
        sb.AppendLine($"Size: {d.Length/1024.0:F1} KB");
        sb.AppendLine($"SHA256: {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(d))[..24]}...");
        sb.AppendLine($"MD5: {Convert.ToHexString(System.Security.Cryptography.MD5.HashData(d))[..16]}...");
        if(d.Length>0x3C){
            int pe = BitConverter.ToInt32(d,0x3C);
            sb.AppendLine($"PE offset: 0x{pe:X}");
            if(pe+6<d.Length) sb.AppendLine($"Sections: {BitConverter.ToUInt16(d,pe+6)}");
            if(pe+24<d.Length){
                ushort magic=BitConverter.ToUInt16(d,pe+24);
                sb.AppendLine($"Arch: {(magic==0x10b?"PE32 (32-bit)": magic==0x20b?"PE32+ (64-bit)":"?")}");
                sb.AppendLine($"Subsystem: {DetectSubsystem(d,pe)}");
            }
        }
        var rich = Encoding.ASCII.GetString(d).Contains("Rich") ? "Rich header: Yes (MSVC)" : "Rich header: No";
        sb.AppendLine(rich);
        sb.AppendLine($"IsPacked: {(IsPacked(d)?"Likely UPX/Packer (entropy high)":"No")}");
        sb.AppendLine($"Timestamp: {GetTimestamp(d)}");
        return sb.ToString();
    }

    static string DetectSubsystem(byte[] d,int pe)
    {
        try{
            int optOff=pe+24;
            ushort magic=BitConverter.ToUInt16(d,optOff);
            int subOff=optOff + (magic==0x10b?68:92);
            ushort sub=BitConverter.ToUInt16(d,subOff);
            return sub switch{2=>"GUI",3=>"Console",_=>sub.ToString()};
        }catch{ return "?"; }
    }

    static string GetTimestamp(byte[] d)
    {
        try{
            int pe=BitConverter.ToInt32(d,0x3C);
            int ts=BitConverter.ToInt32(d,pe+8);
            var dt = DateTimeOffset.FromUnixTimeSeconds(ts).DateTime;
            return dt.ToString("yyyy-MM-dd HH:mm:ss") + $" (0x{ts:X})";
        }catch{ return "?"; }
    }

    static bool IsPacked(byte[] d)
    {
        var s = Encoding.ASCII.GetString(d);
        return s.Contains("UPX")|| s.Contains("FSG")|| s.Contains("MPRESS")|| s.Contains("Themida")|| s.Contains("VMProtect");
    }

    static List<string> ExtractStrings(byte[] d, Action<string> log)
    {
        var cur=new StringBuilder(); var list=new List<string>();
        for(int i=0;i<d.Length;i++){
            byte b=d[i];
            if(b>=32&&b<=126) cur.Append((char)b);
            else { if(cur.Length>=4) list.Add(cur.ToString()); cur.Clear(); }
        }
        var filtered = list.Distinct().Where(s=> s.Length>=4 && s.Length<300 && !s.All(char.IsDigit) && s.Length>3).ToList();
        var interesting = filtered.Where(s=> Regex.IsMatch(s, @"(http|https|ftp|\\|\.dll|\.exe|Error|fail|pass|key|api|token|secret|password|admin|config|http|www|\.py|\.pyd|SOFTWARE|Microsoft)")).Take(800).ToList();
        // Try XOR deobfuscate for common keys
        var xored = TryXorDeobfuscate(d, interesting, log);
        if (xored.Count>0) interesting.AddRange(xored);
        return interesting.Count>100? interesting.Distinct().Take(2000).ToList() : filtered.Distinct().Take(2000).ToList();
    }

    static List<string> TryXorDeobfuscate(byte[] d, List<string> existing, Action<string> log)
    {
        var res=new List<string>();
        byte[] keys=new byte[]{0x42,0x55,0xAA,0xFF};
        foreach(var k in keys)
        {
            var sb=new StringBuilder(); int count=0;
            for(int i=0;i<Math.Min(d.Length,50000);i++){
                byte b=(byte)(d[i]^k);
                if(b>=32&&b<=126) sb.Append((char)b);
                else { if(sb.Length>=8 && Regex.IsMatch(sb.ToString(),@"(http|key|pass)")) { res.Add($"[XOR 0x{k:X2}] "+sb.ToString()); count++; } sb.Clear(); if(count>20) break; }
            }
        }
        if(res.Count>0) log($"[Killer] XOR deobfuscated: {res.Count} strings");
        return res;
    }

    static List<string> ExtractImports(byte[] d)
    {
        var txt=Encoding.ASCII.GetString(d);
        var dlls=Regex.Matches(txt, @"[A-Za-z0-9_]+\.dll").Select(x=>x.Value).Distinct().Take(30).ToList();
        var apis=Regex.Matches(txt, @"(VirtualAlloc|CreateThread|WriteProcessMemory|VirtualProtect|LoadLibrary|GetProcAddress|IsDebuggerPresent|NtQueryInformationProcess)").Select(x=>x.Value).Distinct().ToList();
        var all=new List<string>(); all.AddRange(dlls); all.AddRange(apis);
        return all.Distinct().Take(80).ToList();
    }

    static string BuildHexDump(byte[] d)
    {
        var sb=new StringBuilder();
        for(int i=0;i<Math.Min(d.Length, 8192); i+=16){
            sb.Append($"{i:X8}  ");
            for(int j=0;j<16;j++) sb.Append(i+j<d.Length? $"{d[i+j]:X2} ":"   ");
            sb.Append(" |");
            for(int j=0;j<16&&i+j<d.Length;j++) sb.Append(d[i+j]>=32&&d[i+j]<=126?(char)d[i+j]:'.');
            sb.AppendLine("|");
        }
        sb.AppendLine($"\n... truncated {d.Length} bytes total");
        return sb.ToString();
    }

    static string DetectCompiler(byte[] d)
    {
        var s=Encoding.ASCII.GetString(d);
        if(s.Contains("GCC")) return "MinGW GCC (Killer: try ghidra with gcc profile)";
        if(s.Contains("Rich")|| s.Contains("MSVC")|| s.Contains("Visual C++")) return "Microsoft Visual C++ (MSVC) - Killer: Rich header present, use MSVC demangler";
        if(s.Contains("Borland")) return "Borland C++";
        if(s.Contains("clang")) return "Clang/LLVM - Killer: try retdec";
        if(s.Contains("UPX")) return "UPX Packed (Killer: unpack with upx -d first)";
        if(s.Contains("Go")) return "Go (Killer: try goresym)";
        if(s.Contains("Rust")) return "Rust (Killer: try rust demangle)";
        return "Unknown Native C/C++ (PE) - Killer: generic, try capstone + ghidra";
    }

    static string RunYara(byte[] d, Action<string> log)
    {
        var sb=new StringBuilder();
        sb.AppendLine("[YARA Killer Scan]");
        var txt=Encoding.ASCII.GetString(d);
        void Rule(string name,string pat){ if(Regex.IsMatch(txt,pat,RegexOptions.IgnoreCase)) sb.AppendLine($"  [!] {name}"); }
        Rule("UPX Packer", @"UPX0|UPX1");
        Rule("Themida", @"Themida|WinLicense");
        Rule("VMProtect", @"VMProtect|VMP\.dll");
        Rule("PyInstaller", @"PyInstaller|pyi-");
        Rule("Nuitka", @"Nuitka");
        Rule("PyArmor", @"pyarmor|pytransform");
        Rule("Anti-Debug", @"IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess");
        Rule("Network", @"http://|https://|WSAStartup|connect\(|recv\(|send\(");
        Rule("Crypto", @"CryptEncrypt|BCrypt|OpenSSL|AES|ChaCha");
        Rule("Keylogger", @"GetAsyncKeyState|SetWindowsHookEx|keyboard");
        if(sb.ToString().Split('\n').Length<3) sb.AppendLine("  [OK] No obvious YARA hits (clean)");
        return sb.ToString();
    }

    static async Task<string> TryCapstone(string exe, string outDir, Action<string> log)
    {
        try
        {
            string script=Path.Combine(AppContext.BaseDirectory,"Assets","cpp_capstone.py");
            if(!File.Exists(script)) return "[Capstone] script not found";
            string outAsm=Path.Combine(outDir,"capstone.asm");
            var psi=new ProcessStartInfo("python",$" \"{script}\" \"{exe}\" \"{outAsm}\""){ RedirectStandardOutput=true, UseShellExecute=false, CreateNoWindow=true };
            using var p=Process.Start(psi);
            if(p!=null){ string o=await p.StandardOutput.ReadToEndAsync(); await p.WaitForExitAsync(); log($"[Killer] Capstone: {o.Trim()}"); if(File.Exists(outAsm)) return $"Capstone: {new FileInfo(outAsm).Length/1024}KB disassembled"; }
        } catch(Exception ex){ log($"[Capstone] fail: {ex.Message}"); }
        return "[Capstone] not available";
    }

    static string AnalyzeEntropy(byte[] d, Action<string> log)
    {
        var sb=new StringBuilder();
        sb.AppendLine("[Entropy Killer]");
        try{
            int pe=BitConverter.ToInt32(d,0x3C);
            ushort num=BitConverter.ToUInt16(d,pe+6);
            ushort optSize=BitConverter.ToUInt16(d,pe+20);
            int secOff=pe+24+optSize;
            for(int i=0;i<num && secOff+40<=d.Length;i++){
                string name=Encoding.ASCII.GetString(d,secOff,8).Trim('\0');
                int rawSize=BitConverter.ToInt32(d,secOff+16);
                int rawPtr=BitConverter.ToInt32(d,secOff+20);
                if(rawPtr+rawSize>d.Length || rawSize==0){ secOff+=40; continue; }
                double ent=CalcEntropy(d,rawPtr,rawSize);
                sb.AppendLine($"  {name.PadRight(8)} entropy {ent:F2} {(ent>7.0?"[PACKED]":"")}{(ent<5.0?"[CODE]":"")}");
                secOff+=40;
            }
        }catch{}
        return sb.ToString();
    }

    static double CalcEntropy(byte[] d,int off,int len){
        var freq=new int[256];
        int n=Math.Min(len, d.Length-off);
        for(int i=0;i<n;i++) freq[d[off+i]]++;
        double e=0;
        foreach(var c in freq) if(c>0){ double p=(double)c/n; e-=p*Math.Log2(p); }
        return e;
    }

    static string DetectAnti(byte[] d, Action<string> log)
    {
        var txt=Encoding.ASCII.GetString(d);
        var sb=new StringBuilder();
        sb.AppendLine("[Anti Killer]");
        if(txt.Contains("IsDebuggerPresent")||txt.Contains("BeingDebugged")) sb.AppendLine("  Anti-Debug: IsDebuggerPresent/PEB");
        if(txt.Contains("NtQueryInformationProcess")) sb.AppendLine("  Anti-Debug: NtQueryInformationProcess");
        if(txt.Contains("OutputDebugString")) sb.AppendLine("  Anti-Debug: OutputDebugString");
        if(txt.Contains("FindWindow")&&txt.Contains("OLLYDBG")) sb.AppendLine("  Anti-VM: OllyDbg check");
        if(txt.Contains("VMware")||txt.Contains("VirtualBox")||txt.Contains("QEMU")) sb.AppendLine("  Anti-VM: VM strings");
        if(txt.Contains("Wireshark")||txt.Contains("Fiddler")) sb.AppendLine("  Anti-Analysis: Network sniffer check");
        if(sb.ToString().Split('\n').Length<3) sb.AppendLine("  No obvious anti tricks");
        return sb.ToString();
    }
}
