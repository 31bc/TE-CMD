using System;
using System.Collections.Generic;

namespace SampleNet
{
    /// <summary>Small deterministic library used as the .NET decompile test target.</summary>
    public static class Calculator
    {
        public static int Add(int a, int b) { return a + b; }

        public static string Describe(IEnumerable<int> values)
        {
            int sum = 0;
            int count = 0;
            foreach (int v in values) { sum += v; count++; }
            return string.Format("{0} values, sum {1}", count, sum);
        }

        public static bool IsEven(int value)
        {
            return value % 2 == 0;
        }
    }
}
