using System;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Research.SEAL;
using portableSEAL.Services;
using static Server.Utils.Util;
using static Server.Utils.Serializer;
using Evaluator = portableSEAL.Services.Evaluator;

namespace Server.Services
{
    public class EvaluatorService : Evaluator.EvaluatorBase
    {
        private SEALContext _context;
        private KeyGenerator _generator;
        private IntegerEncoder _encoder;
        private Ciphertext _ct;
        private Microsoft.Research.SEAL.Evaluator _evaluator;

        public override Task<Nothing> Create(CiphertextId request, ServerCallContext context) => RunNothing(() =>
        {
            _context = ContextService.GetContext();
            _encoder = ContextService.GetIntegerEncoder();
            if (_context == null || _encoder == null)
                throw NewRpcException(StatusCode.FailedPrecondition,
                    "improperly initialized Context. create a valid Context first");
            _ct = ContextService.GetCiphertext(request);
            if (_ct == null)
                throw NewRpcException(StatusCode.NotFound, "nonexistent CiphertextId");
            _generator = new KeyGenerator(_context); // for relinearization only
            _evaluator = new Microsoft.Research.SEAL.Evaluator(_context);
        });

        public override Task<SerializedCiphertext> Result(Nothing request, ServerCallContext context) =>
            Task.Run(() => SerializeCiphertext(_ct));

        public override Task<Nothing> Add(BinaryOperand request, ServerCallContext context) => RunNothing(() =>
        {
            InvokeInplace(request,
                ct => _evaluator.AddInplace(_ct, ct),
                pt => _evaluator.AddPlainInplace(_ct, pt));
        });

        public override Task<Nothing> Sub(BinaryOperand request, ServerCallContext context) => RunNothing(() =>
        {
            InvokeInplace(request,
                ct => _evaluator.SubInplace(_ct, ct),
                pt => _evaluator.SubPlainInplace(_ct, pt));
        });

        public override Task<Nothing> Multiply(BinaryOperand request, ServerCallContext context) => RunNothing(() =>
        {
            InvokeInplace(request,
                ct => _evaluator.MultiplyInplace(_ct, ct),
                pt => _evaluator.MultiplyPlainInplace(_ct, pt));
        });

        public override Task<Nothing> Negate(Nothing request, ServerCallContext context) => RunNothing(() =>
        {
            _evaluator.NegateInplace(_ct);
        });

        public override Task<Nothing> Relinearize(Nothing request, ServerCallContext context) => RunNothing(() =>
        {
            _evaluator.RelinearizeInplace(_ct, _generator.RelinKeys());
        });

        private void InvokeInplace(BinaryOperand operand, Action<Ciphertext> action, Action<Plaintext> actionPlain)
        {
            Ciphertext ct = null;
            Plaintext pt = null;
            switch (operand.OperandCase)
            {
                case BinaryOperand.OperandOneofCase.SerializedCiphertext:
                    ct = DeserializeCiphertext(_context, operand.SerializedCiphertext.Data);
                    break;
                case BinaryOperand.OperandOneofCase.CiphertextId:
                    ct = ContextService.GetCiphertext(operand.CiphertextId);
                    break;
                case BinaryOperand.OperandOneofCase.PlaintextData:
                    pt = _encoder.Encode(operand.PlaintextData.Data);
                    break;
                case BinaryOperand.OperandOneofCase.PlaintextId:
                    pt = ContextService.GetPlaintext(operand.PlaintextId);
                    break;
                case BinaryOperand.OperandOneofCase.None:
                    throw NewRpcException(StatusCode.InvalidArgument, "must provide Plaintext or Ciphertext");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            if (ct != null) action.Invoke(ct);
            else actionPlain.Invoke(pt);
        }

        private readonly ILogger<EvaluatorService> _logger;
        public EvaluatorService(ILogger<EvaluatorService> logger) => _logger = logger;
    }
}