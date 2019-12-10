using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Tests.Helpers
{
    [ExcludeFromCodeCoverage]
    public static class MockData
    {
        private static readonly Random Random = new Random();

        public static IEnumerable<long> LongSource()
        {
            yield return long.MaxValue;
            yield return long.MinValue;
            for (var i = 0; i < 10; i++)
                yield return RandomLong();
        }

        private static long RandomLong()
        {
            var buf = new byte[8];
            Random.NextBytes(buf);
            return BitConverter.ToInt64(buf);
        }
    }
}