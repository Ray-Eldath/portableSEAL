using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using portableSEAL.Services;
using portableSEAL.Services.Switcher;
using static Server.Utils.Util;

namespace Server.Services.Switcher
{
    public class EvaluatorSwitcherService : EvaluatorSwitcher.EvaluatorSwitcherBase
    {
        private readonly List<EvaluatorDelegation> _evaluators = new List<EvaluatorDelegation>();
        private int _current = -1;

        public override Task<Nothing> Clear(Nothing request, ServerCallContext context) => RunNothing(() =>
        {
            _current = -1;
            _evaluators.Clear();
        });

        public override Task<Position> AddNew(CiphertextId request, ServerCallContext context) => Task.Run(() =>
        {
            var evaluator = new EvaluatorDelegation(_logger);
            evaluator.Create(request, context);
            _evaluators.Add(evaluator);
            return new Position {Pos = ++_current};
        });

        public override Task<Position> Next(Nothing request, ServerCallContext context) => Task.Run(() =>
        {
            EvaluatorService.SetDelegation(GetElementAtOrThrow(++_current));
            return new Position {Pos = _current};
        });

        public override Task<Position> Previous(Nothing request, ServerCallContext context) => Task.Run(() =>
        {
            EvaluatorService.SetDelegation(GetElementAtOrThrow(--_current));
            return new Position {Pos = _current};
        });

        public override Task<Nothing> At(Position request, ServerCallContext context) => RunNothing(() =>
            EvaluatorService.SetDelegation(GetElementAtOrThrow(request.Pos)));

        private EvaluatorDelegation GetElementAtOrThrow(int pos)
        {
            if (pos < 0 || _evaluators.ElementAt(pos) == null)
                throw NewRpcException(StatusCode.NotFound,
                    $"invalid or nonexistent Evaluator at position {pos}. check your parameter or AddNew?");
            return _evaluators[pos];
        }

        private readonly ILogger<EvaluatorService> _logger;
        public EvaluatorSwitcherService(ILogger<EvaluatorService> logger) => _logger = logger;
    }
}