using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Grpc.Core;
using portableSEAL.Services;

namespace Server.Utils
{
    public static class Util
    {
        private static readonly Nothing Nothing = new Nothing();

        public static Task<Nothing> SafeRunNothing(Action action) =>
            SafeRun(() =>
            {
                action.Invoke();
                return Nothing;
            });

        public static Task<T> SafeRunAsync<T>(Func<Task<T>> action, StatusCode failedCode = StatusCode.Internal) =>
            SafeRun(() => action.Invoke().Result, failedCode);

        public static Task<T> SafeRun<T>(Func<T> action, StatusCode failedCode = StatusCode.Internal)
        {
            try
            {
                return Task.Run(action.Invoke);
            }
            catch (Exception e)
            {
                throw NewRpcException(failedCode, e.Message);
            }
        }

        public static RpcException NewRpcException(StatusCode code, string reason) =>
            new RpcException(new Status(code, reason), reason);

        public static string ToSizeString(long bytes)
        {
            const int unit = 1000;
            var unitStr = "b";
            if (bytes < unit) return $"{bytes} {unitStr}";
            unitStr = unitStr.ToUpper();
            var exp = (int) (Math.Log(bytes) / Math.Log(unit));
            return $"{bytes / Math.Pow(unit, exp):##.##} {"KMGTPEZY"[exp - 1]}{unitStr}";
        }

        public static TE GetOrThrow<T, TE>(string name, Dictionary<T, TE> map, T key)
        {
            if (map.ContainsKey(key) == false)
                throw NewRpcException(StatusCode.InvalidArgument, $"nonexistent {name}");
            return map[key];
        }
    }
}