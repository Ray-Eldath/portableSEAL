using Grpc.Core;
using portableSEAL.Services;

// ReSharper disable InconsistentNaming

namespace Tests.Helpers
{
    public static class Constants
    {
        internal const long Min = long.MinValue, Max = long.MaxValue, SafeMin = int.MinValue, SafeMax = int.MaxValue;

        internal static readonly Nothing _nothing = new Nothing();
        internal static readonly ServerCallContext _mockContext = MockServerCallContext.Create();
    }
}