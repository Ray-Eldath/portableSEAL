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

        public static Task<Nothing> RunNothing(Action action) => Task.Run(() =>
        {
            action.Invoke();
            return Nothing;
        });

        public static RpcException NewRpcException(StatusCode statusCode, string reason) =>
            new RpcException(new Status(statusCode, ""), reason);

        public static TE GetOrThrow<T, TE>(string name, Dictionary<T, TE> map, T key)
        {
            if (map.ContainsKey(key) == false)
                throw NewRpcException(StatusCode.InvalidArgument, $"nonexistent {name}");
            return map[key];
        }
    }
}