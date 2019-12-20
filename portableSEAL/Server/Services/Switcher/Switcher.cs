using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using portableSEAL.Services;
using portableSEAL.Services.Switcher;
using static Server.Utils.Util;
using static Server.Services.Switcher.SwitcherParameterHolder;

namespace Server.Services.Switcher
{
    public class EvaluatorSwitcherService : EvaluatorSwitcher.EvaluatorSwitcherBase
    {
        public override Task<Nothing> Clear(Nothing request, ServerCallContext context) => SafeRunNothing(() =>
        {
            Current = -1;
            Evaluators.ForEach(e => e.Destroy(request, context));
            Evaluators.Clear();
        });

        public override Task<Position> ConstructNew(SerializedCiphertext request, ServerCallContext context) =>
            AddNew(BfvContextService.ParseCiphertext(request).Result, context);

        private Task<Position> AddNew(CiphertextId request, ServerCallContext context) => SafeRunAsync(async () =>
        {
            var evaluator = new EvaluatorDelegation(_logger);
            await evaluator.Create(request, context);

            Evaluators.Add(evaluator);
            ++Current;
            // Console.WriteLine(_current + ": " + GetElementAtOrThrow(_current).GetHashCode());
            EvaluatorService.SetDelegation(GetElementAtOrThrow(Current));
            return new Position {Pos = Current};
        });

        public override Task<Position> Next(Nothing request, ServerCallContext context) => SafeRun(() =>
        {
            EvaluatorService.SetDelegation(GetElementAtOrThrow(++Current));
            // Console.WriteLine("now: {0}", _current);
            return new Position {Pos = Current};
        });

        public override Task<Position> Previous(Nothing request, ServerCallContext context) => SafeRun(() =>
        {
            EvaluatorService.SetDelegation(GetElementAtOrThrow(--Current));
            // Console.WriteLine("now: {0}", _current);
            return new Position {Pos = Current};
        });

        public override Task<Nothing> At(Position request, ServerCallContext context) => SafeRunNothing(() =>
            EvaluatorService.SetDelegation(GetElementAtOrThrow(request.Pos)));

        private EvaluatorDelegation GetElementAtOrThrow(int pos)
        {
            if (pos < 0 || pos > Evaluators.Count - 1 || Evaluators.ElementAt(pos) == null)
                throw NewRpcException(StatusCode.NotFound,
                    $"invalid or nonexistent Evaluator at position {pos}. check your parameter or AddNew?");
            return Evaluators[pos];
        }

        private readonly ILogger<EvaluatorService> _logger;
        public EvaluatorSwitcherService(ILogger<EvaluatorService> logger) => _logger = logger;
    }

    internal static class SwitcherParameterHolder
    {
        internal static readonly List<EvaluatorDelegation> Evaluators = new List<EvaluatorDelegation>();
        internal static int Current = -1;
    }
}