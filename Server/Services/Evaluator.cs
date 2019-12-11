using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using portableSEAL.Services;

namespace Server.Services
{
    public class EvaluatorService : Evaluator.EvaluatorBase
    {
        public override Task<Nothing> Create(CiphertextId request, ServerCallContext context)
        {
            return base.Create(request, context);
        }

        public override Task<SerializedCiphertext> Result(Nothing request, ServerCallContext context)
        {
            return base.Result(request, context);
        }

        public override Task<Nothing> Add(BinaryOperand request, ServerCallContext context)
        {
            return base.Add(request, context);
        }

        public override Task<Nothing> Sub(BinaryOperand request, ServerCallContext context)
        {
            return base.Sub(request, context);
        }

        public override Task<Nothing> Multiply(BinaryOperand request, ServerCallContext context)
        {
            return base.Multiply(request, context);
        }

        public override Task<Nothing> Negate(Nothing request, ServerCallContext context)
        {
            return base.Negate(request, context);
        }

        public override Task<Nothing> Relinearize(Nothing request, ServerCallContext context)
        {
            return base.Relinearize(request, context);
        }

        private readonly ILogger<ContextService> _logger;

        public EvaluatorService(ILogger<ContextService> logger) => _logger = logger;
    }
}