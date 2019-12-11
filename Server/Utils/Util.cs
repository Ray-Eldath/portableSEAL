using System;
using System.Threading.Tasks;
using Grpc.Core;
using portableSEAL.Services;

namespace Server.Utils
{
    internal static class Util
    {
        private static readonly Nothing Nothing = new Nothing();

        internal static Task<Nothing> RunNothing(Action action) => Task.Run(() =>
        {
            action.Invoke();
            return Nothing;
        });

        internal static RpcException NewRpcException(StatusCode statusCode, string reason) =>
            new RpcException(new Status(statusCode, ""), reason);
    }
}