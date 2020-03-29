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
    internal class EvaluatorDelegation : Evaluator.EvaluatorBase
    {
        private SEALContext _context;
        private KeyGenerator _generator;
        private IntegerEncoder _encoder;
        private Ciphertext _ct;
        private CiphertextId _ctId;
        private Microsoft.Research.SEAL.Evaluator _evaluator;

        #region Instance

        public override Task<Nothing> Construct(SerializedCiphertext request, ServerCallContext context) =>
            Create(BfvContextService.ParseCiphertext(request).Result, context);
        // 2019-12-20：
        // 
        // 这里爆出了我迄今为止最长debug时间的一个bug。大概debug了三个钟。
        // 原代码：
        // public override Task<Nothing> Construct(SerializedCiphertext request, ServerCallContext context) =>
        //     SafeRunNothing(async () => await Create(await BfvContextService.ParseCiphertext(request), context));
        // 
        // 仿照 EvaluatorSwitcher 中使用 Result 的模式改为现在这个样子，测试通过。
        // 一点侥幸的是当时 EvaluatorSwitcher 用 Result 完全就是 “更好看”，根本没有多想......
        // 
        // 明显是由于自己对协程理解不够导致的问题...... 今后要多学习基础知识。少弄些垃圾玩意。
        // 谨以此为戒。
        // 
        // Ray Eldath.
        //

        public override Task<Nothing> Create(CiphertextId request, ServerCallContext context) => SafeRunNothing(() =>
        {
            _context = BfvContextService.GetContext();
            _encoder = BfvContextService.GetIntegerEncoder();
            if (_context == null || _encoder == null)
                throw NewRpcException(StatusCode.FailedPrecondition,
                    "improperly initialized Context. create a valid Context first");
            //
            _ctId = request;
            _ct = BfvContextService.GetCiphertext(request);
            if (_ct == null)
                throw NewRpcException(StatusCode.NotFound, "nonexistent CiphertextId");
            _generator = new KeyGenerator(_context); // for relinearization only
            _evaluator = new Microsoft.Research.SEAL.Evaluator(_context);
        });

        public override Task<Nothing> Destroy(Nothing request, ServerCallContext context) =>
            SafeRunNothing(BfvContextService.Clear);

        #endregion

        #region State

        public override Task<SerializedCiphertext> Current(Nothing request, ServerCallContext context) =>
            SafeRun(() => SerializeCiphertext(_ct));

        public override Task<CiphertextId> GetId(Nothing request, ServerCallContext context) =>
            SafeRun(() => _ctId);

        #endregion

        #region Arthmetical

        public override Task<Nothing> Add(BinaryOperand request, ServerCallContext context) => SafeRunNothing(() =>
        {
            InvokeInplace(request,
                ct => _evaluator.AddInplace(_ct, ct),
                pt => _evaluator.AddPlainInplace(_ct, pt));
        });

        public override Task<Nothing> Sub(BinaryOperand request, ServerCallContext context) => SafeRunNothing(() =>
        {
            InvokeInplace(request,
                ct => _evaluator.SubInplace(_ct, ct),
                pt => _evaluator.SubPlainInplace(_ct, pt));
        });

        public override Task<Nothing> Multiply(BinaryOperand request, ServerCallContext context) => SafeRunNothing(() =>
        {
            InvokeInplace(request,
                ct => _evaluator.MultiplyInplace(_ct, ct),
                pt => _evaluator.MultiplyPlainInplace(_ct, pt));
        });

        public override Task<Nothing> Square(Nothing request, ServerCallContext context) => SafeRunNothing(() =>
        {
            _evaluator.SquareInplace(_ct);
        });

        public override Task<Nothing> Negate(Nothing request, ServerCallContext context) => SafeRunNothing(() =>
        {
            _evaluator.NegateInplace(_ct);
        });

        public override Task<Nothing> Relinearize(Nothing request, ServerCallContext context) => SafeRunNothing(() =>
        {
            _evaluator.RelinearizeInplace(_ct, _generator.RelinKeys());
        });

        #endregion

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
                    ct = BfvContextService.GetCiphertext(operand.CiphertextId);
                    break;
                case BinaryOperand.OperandOneofCase.PlaintextData:
                    pt = _encoder.Encode(operand.PlaintextData.Data);
                    break;
                case BinaryOperand.OperandOneofCase.PlaintextId:
                    pt = BfvContextService.GetPlaintext(operand.PlaintextId);
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

        public EvaluatorDelegation(ILogger<EvaluatorService> logger) => _logger = logger;
    }

    public class EvaluatorService : Evaluator.EvaluatorBase
    {
        private static EvaluatorDelegation _delegation;

        internal static void SetDelegation(EvaluatorDelegation delegation) => _delegation = delegation;

        public override Task<Nothing> Construct(SerializedCiphertext request, ServerCallContext context)
        {
            _delegation = new EvaluatorDelegation(_logger);
            return _delegation.Construct(request, context);
        }

        public override Task<Nothing> Create(CiphertextId request, ServerCallContext context)
        {
            _delegation = new EvaluatorDelegation(_logger);
            return _delegation.Create(request, context);
        }

        public override Task<Nothing> Destroy(Nothing request, ServerCallContext context) =>
            _delegation.Destroy(request, context);

        public override Task<CiphertextId> GetId(Nothing request, ServerCallContext context) =>
            _delegation.GetId(request, context);

        public override Task<SerializedCiphertext> Current(Nothing request, ServerCallContext context) =>
            _delegation.Current(request, context);

        public override Task<Nothing> Add(BinaryOperand request, ServerCallContext context) =>
            _delegation.Add(request, context);

        public override Task<Nothing> Sub(BinaryOperand request, ServerCallContext context) =>
            _delegation.Sub(request, context);

        public override Task<Nothing> Multiply(BinaryOperand request, ServerCallContext context) =>
            _delegation.Multiply(request, context);

        public override Task<Nothing> Square(Nothing request, ServerCallContext context) =>
            _delegation.Square(request, context);

        public override Task<Nothing> Negate(Nothing request, ServerCallContext context) =>
            _delegation.Negate(request, context);

        public override Task<Nothing> Relinearize(Nothing request, ServerCallContext context) =>
            _delegation.Relinearize(request, context);

        private readonly ILogger<EvaluatorService> _logger;
        public EvaluatorService(ILogger<EvaluatorService> logger) => _logger = logger;
    }
}