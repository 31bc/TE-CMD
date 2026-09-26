using System.IO;
using System.Text;

namespace DecompilerSuite.Helpers;

enum PackerType { Unknown, PyInstaller, Nuitka, DotNet, Cpp, PyArmor, Themida, Pyz, Mixed }

static class Detector
{
    public static PackerType Detect(string path)
    {
        var data = File.ReadAllBytes(path);
        var txt = Encoding.ASCII.GetString(data);
        var txtLow = txt.ToLowerInvariant();
        bool isDotNet = IsDotNet(data);
        if (isDotNet)
        {
            if (txt.Contains("PyInstaller") || txt.Contains("pyi-")) return PackerType.PyInstaller;
            if (HasNuitkaOneFileHeuristics(data, txt, txtLow)) return PackerType.Nuitka;
            if (txt.Contains("Nuitka")) return PackerType.Nuitka;
            if (txt.Contains("pyarmor") || txtLow.Contains("pyarmor")) return PackerType.PyArmor;
            return PackerType.DotNet;
        }
        if (txt.Contains("pyarmor") || txtLow.Contains("pyarmor") || txt.Contains("pytransform")) return PackerType.PyArmor;
        if (txt.Contains("Themida") || txt.Contains("WinLicense") || txt.Contains("Oreans")) return PackerType.Themida;
        if (HasNuitkaOneFileHeuristics(data, txt, txtLow)) return PackerType.Nuitka;
        if (txt.Contains("Nuitka") || txt.Contains("nuitka")) return PackerType.Nuitka;
        if (txt.Contains("PyInstaller") || txt.Contains("pyi-") || HasPyInstallerMagic(data)) return PackerType.PyInstaller;
        if (txt.Contains("PYZ") && txt.Contains("pyz")) return PackerType.Pyz;
        if (IsPeFile(data)) return PackerType.Cpp;
        return PackerType.Unknown;
    }

    static bool HasNuitkaOneFileHeuristics(byte[] data, string txt, string txtLow)
    {
        if (data.Length < 1000) return false;
        bool hasNuitkaStr = txt.Contains("Nuitka") || txtLow.Contains("nuitka") ||
                            txt.Contains("onefile") || txt.Contains("onefile_mode");
        bool hasZstdInRdata = HasZstdInRdata(data);
        bool hasNuitkaCompileMarker = txt.Contains("compiled by Nuitka") || txt.Contains("Nuitka compiler");
        int score = 0;
        if (hasNuitkaStr) score += 2;
        if (hasZstdInRdata) score += 3;
        if (hasNuitkaCompileMarker) score += 2;
        if (score >= 3) return true;
        if (hasZstdInRdata && IsPeFile(data)) return true;
        return false;
    }

    static bool HasZstdInRdata(byte[] data)
    {
        try
        {
            if (!IsPeFile(data)) return false;
            int peOff = BitConverter.ToInt32(data, 0x3C);
            short numSections = BitConverter.ToInt16(data, peOff + 6);
            int optOff = peOff + 24;
            short optSize = BitConverter.ToInt16(data, peOff + 20);
            int sectionOff = optOff + optSize;
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionOff + i * 40;
                string name = Encoding.ASCII.GetString(data, off, 8).TrimEnd('\0');
                if (name == ".rdata")
                {
                    int rawSize = BitConverter.ToInt32(data, off + 16);
                    int rawPtr = BitConverter.ToInt32(data, off + 20);
                    if (rawPtr + 4 > data.Length) return false;
                    for (int j = rawPtr; j < Math.Min(rawPtr + rawSize - 4, data.Length - 4); j++)
                    {
                        if (data[j] == 0x28 && data[j + 1] == 0xB5 && data[j + 2] == 0x2F && data[j + 3] == 0xFD)
                            return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }

    public static List<string> DetectAll(string path)
    {
        var list=new List<string>();
        var data=File.ReadAllBytes(path);
        var txt=Encoding.ASCII.GetString(data);
        var txtLow=txt.ToLowerInvariant();
        if(IsDotNet(data)) list.Add(".NET");
        if(HasNuitkaOneFileHeuristics(data, txt, txtLow)) list.Add("Nuitka OneFile");
        if(txt.Contains("PyInstaller")||HasPyInstallerMagic(data)) list.Add("PyInstaller");
        if(txt.Contains("Nuitka")||txtLow.Contains("nuitka")) list.Add("Nuitka");
        if(txtLow.Contains("pyarmor")) list.Add("PyArmor");
        if(txt.Contains("Themida")||txt.Contains("WinLicense")) list.Add("Themida");
        if(txt.Contains("UPX")) list.Add("UPX");
        if(txt.Contains("VMProtect")) list.Add("VMProtect");
        if(txt.Contains("Enigma")) list.Add("Enigma");
        if(list.Count==0) list.Add("Native PE");
        return list;
    }

    static bool HasPyInstallerMagic(byte[] d)
    {
        byte[] magic = new byte[]{0x4D,0x45,0x49,0x0C,0x0B,0x0A,0x0B,0x0E};
        for (int i = Math.Max(0,d.Length-500000); i < d.Length-8; i++)
        {
            bool ok=true; for(int j=0;j<8;j++) if(d[i+j]!=magic[j]){ ok=false; break; }
            if(ok) return true;
        }
        return d.Length>100 && Encoding.ASCII.GetString(d).Contains("pyi-");
    }

    static bool IsPeFile(byte[] d) => d.Length > 2 && d[0] == 'M' && d[1] == 'Z';

    static bool IsDotNet(byte[] d)
    {
        try
        {
            if (!IsPeFile(d)) return false;
            int peOff = BitConverter.ToInt32(d, 0x3C);
            if (peOff + 6 > d.Length) return false;
            int optOff = peOff + 24;
            ushort magic = BitConverter.ToUInt16(d, optOff);
            bool is32 = magic == 0x10b;
            int dataDirOff = optOff + (is32 ? 96 : 112);
            if (dataDirOff + 16*8 > d.Length) return false;
            int clrRva = BitConverter.ToInt32(d, dataDirOff + 14*8);
            int clrSize = BitConverter.ToInt32(d, dataDirOff + 14*8 + 4);
            return clrRva != 0 && clrSize != 0;
        } catch { return false; }
    }

    public static string Describe(PackerType t) => t switch
    {
        PackerType.PyInstaller => "PyInstaller (Python)",
        PackerType.Nuitka => "Nuitka (Python Compiled)",
        PackerType.DotNet => "C# / .NET (.dll/.exe)",
        PackerType.Cpp => "C/C++ Native PE",
        PackerType.PyArmor => "PyArmor (Obfuscated)",
        PackerType.Themida => "Themida/WinLicense (Packed)",
        PackerType.Pyz => "PYZ Archive (PyInstaller)",
        PackerType.Mixed => "Mixed / Unknown",
        _ => "Unknown - will try auto detection"
    };
}
