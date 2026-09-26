using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DecompilerSuite.Helpers;

static class PeHelper
{
    public static string GetPeInfo(string path)
    {
        var sb = new StringBuilder();
        var d = File.ReadAllBytes(path);
        sb.AppendLine($"Size: {d.Length / 1024.0:F1} KB");
        sb.AppendLine($"PE: {(d[0]=='M'&&d[1]=='Z'?"Yes":"No")}");
        if (d.Length < 0x40) return sb.ToString();
        int pe = BitConverter.ToInt32(d, 0x3C);
        sb.AppendLine($"PE Offset: 0x{pe:X}");
        if (pe + 6 < d.Length)
        {
            ushort sections = BitConverter.ToUInt16(d, pe + 6);
            sb.AppendLine($"Sections: {sections}");
            sb.AppendLine($"Arch: {(Is64Bit(d,pe)?"64-bit":"32-bit")}");
        }
        var ver = FileVersionInfo.GetVersionInfo(path);
        if (!string.IsNullOrEmpty(ver.FileVersion)) sb.AppendLine($"Version: {ver.FileVersion}");
        if (!string.IsNullOrEmpty(ver.CompanyName)) sb.AppendLine($"Company: {ver.CompanyName}");
        if (!string.IsNullOrEmpty(ver.ProductName)) sb.AppendLine($"Product: {ver.ProductName}");
        sb.AppendLine($"Compiled: {File.GetCreationTime(path):yyyy-MM-dd HH:mm}");
        sb.AppendLine($"SHA256: {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(d))[..16]}...");
        return sb.ToString();
    }

    static bool Is64Bit(byte[] d,int pe)
    {
        try{ ushort magic=BitConverter.ToUInt16(d, pe+24); return magic==0x20b; }catch{ return false; }
    }

    public static string GetSectionsInfo(string path)
    {
        try
        {
            var d=File.ReadAllBytes(path);
            int pe=BitConverter.ToInt32(d,0x3C);
            ushort num=BitConverter.ToUInt16(d, pe+6);
            ushort optSize=BitConverter.ToUInt16(d, pe+20);
            int secOff=pe+24+optSize;
            var sb=new StringBuilder();
            sb.AppendLine("Sections:");
            for(int i=0;i<num && secOff+40<=d.Length;i++)
            {
                string name=Encoding.ASCII.GetString(d, secOff, 8).Trim('\0');
                int vSize=BitConverter.ToInt32(d, secOff+8);
                int vAddr=BitConverter.ToInt32(d, secOff+12);
                int rawSize=BitConverter.ToInt32(d, secOff+16);
                double ent=CalcEntropy(d, secOff);
                sb.AppendLine($"  {name.PadRight(8)} VA:0x{vAddr:X8} Size:{rawSize/1024}KB Ent:{ent:F1}");
                secOff+=40;
            }
            return sb.ToString();
        }catch(Exception ex){ return "Sections error: "+ex.Message; }
    }

    static double CalcEntropy(byte[] d,int off)
    {
        try{
            var freq=new int[256];
            int len=Math.Min(2048, d.Length-off);
            for(int i=0;i<len;i++) freq[d[off+i]]++;
            double e=0;
            for(int i=0;i<256;i++) if(freq[i]>0){ double p=(double)freq[i]/len; e-=p*Math.Log2(p); }
            return e;
        }catch{ return 0;}
    }

    public static List<string> ExtractStrings(string path, int minLen = 5)
    {
        var bytes = File.ReadAllBytes(path);
        var list = new List<string>();
        var cur = new StringBuilder();
        foreach (var b in bytes)
        {
            if (b >= 32 && b <= 126) cur.Append((char)b);
            else
            {
                if (cur.Length >= minLen) list.Add(cur.ToString());
                cur.Clear();
            }
        }
        var res=list.Where(s=>s.Length>minLen).Distinct().ToList();
        var inter=res.Where(s=> Regex.IsMatch(s, @"(http|ftp|\\|\.dll|\.exe|Error|api|key|pass|http|www|\.py|\.pyd)")).Take(400).ToList();
        return inter.Count>20? inter : res.Take(1000).ToList();
    }

    public static string DetectProtection(string path)
    {
        try{
            var d=File.ReadAllBytes(path);
            var txt=Encoding.ASCII.GetString(d);
            var sb=new StringBuilder();
            sb.AppendLine("🔍 Protection / Packer Scan:");
            bool found=false;
            void Check(string kw,string name){ if(txt.Contains(kw)){ sb.AppendLine($"  ⚠️ {name} ({kw})"); found=true; } }
            Check("UPX","UPX Packed");
            Check("FSG","FSG Packer");
            Check("MPRESS","MPRESS");
            Check("Themida","Themida Protector");
            Check("VMProtect","VMProtect");
            Check("Enigma","Enigma Protector");
            Check("ASPack","ASPack");
            Check("PyArmor","PyArmor (Python Obfuscator)");
            Check("pyarmor","PyArmor");
            Check("PyInstaller","PyInstaller (Python)");
            Check("Nuitka","Nuitka Compiled");
            Check("pyi-","PyInstaller Archive");
            Check("Rich","MSVC Rich Header");
            Check("GCC","MinGW GCC");
            Check("clang","Clang");
            Check(".NET",".NET Assembly");
            if(txt.Contains("python") && txt.Contains("PyInstaller")) Check("python3","Python 3.x");
            if(!found) sb.AppendLine("  ✅ No obvious protection (Unpacked)");
            else sb.AppendLine("  💡 Use appropriate unpacker before decompiling");
            double ent=0; try{ ent=CalcEntropy(d,0); }catch{}
            sb.AppendLine($"  Entropy: {ent:F1}/8.0 {(ent>7.2?"(Packed/Encrypted)":"")}");
            return sb.ToString();
        }catch(Exception ex){ return "Error: "+ex.Message; }
    }

    public static string GetHexDump(byte[] d, int limit=8192)
    {
        var sb=new StringBuilder();
        int len=Math.Min(d.Length, limit);
        for(int i=0;i<len;i+=16){
            sb.Append($"{i:X8}  ");
            for(int j=0;j<16;j++) sb.Append(i+j<len? $"{d[i+j]:X2} ":"   ");
            sb.Append(" |");
            for(int j=0;j<16&&i+j<len;j++) sb.Append(d[i+j]>=32&&d[i+j]<=126?(char)d[i+j]:'.');
            sb.AppendLine("|");
        }
        sb.AppendLine($"\n... total {d.Length} bytes, shown {len}");
        return sb.ToString();
    }
}
