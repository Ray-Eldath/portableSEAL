using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using portableSEAL.Services;
using Server.Services;
using Server.Services.Switcher;
using Tests.Helpers;
using static Tests.Helpers.Constants;

namespace Tests
{
    [ExcludeFromCodeCoverage]
    [Author("Ray Eldath")]
    [TestFixture(TestName = "test evaluator switcher")]
    public class TestEvaluatorSwitcherService : AbstractEvaluatorTest
    {
        private readonly ServerCallContext _mockContext = MockServerCallContext.Create();
        private readonly EvaluatorSwitcherService _switcher = new EvaluatorSwitcherService(EvaluatorLogger);
        private readonly EvaluatorService _evaluator = new EvaluatorService(EvaluatorLogger);
        private readonly BfvContextService _context = new BfvContextService(new NullLogger<BfvContextService>());
        private KeyPair _keyPair;

        [Test, Description("evaluate \"deep\" polynomial x^2 + 3 * (x - 2) + 4")]
        public void TestDeepPolynomial(
            [Random(SafeMin, SafeMax, 3)] long l) => Assert.DoesNotThrowAsync(async () =>
        {
            var expected = l * l + 3 * (l - 2) + 4;
            Console.WriteLine("{0}^2 + 3 * ({0} - 2) + 4: should be {1}", l, expected);

            var ct = await CreateEvaluator(l, false);
            await _switcher.ConstructNew(ct, _mockContext);

            await _evaluator.Square(_nothing, _mockContext); // part: x^2 || on 0
            await EvaluatorCurrentPlain(true, header: "0 squared");

            await _switcher.ConstructNew(ct, _mockContext); // 1
            // await _evaluator.Relinearize(_nothing, _mockContext);
            await EvaluatorCurrentPlain(false, header: "1 origin");

            await _evaluator.Sub(NewPlaintextData(2), _mockContext);
            await _evaluator.Multiply(NewPlaintextData(3), _mockContext);
            await _evaluator.Add(NewPlaintextData(4), _mockContext); // part: 3 * (x - 2) + 4 || on 0
            await EvaluatorCurrentPlain(true, header: "1");
            var t = await _evaluator.GetId(_nothing, _mockContext);

            await _switcher.Previous(_nothing, _mockContext);
            await _evaluator.Add(new BinaryOperand {CiphertextId = t}, _mockContext);

            Assert.AreEqual(expected, await EvaluatorCurrentPlain(header: "after r"));
        });

        [TearDown]
        public Task TearDownTest() => _switcher.Clear(_nothing, _mockContext);

        [SetUp]
        public Task SetUpTest() => Task.Run(async () =>
        {
            await _context.Create(new ContextParameters
            {
                PlainModulusNumber = 512,
                PolyModulusDegree = 2048
            }, _mockContext);
            //
            _keyPair = await _context.KeyGen(_nothing, _mockContext);
        });

        private static readonly NullLogger<EvaluatorService> EvaluatorLogger = new NullLogger<EvaluatorService>();
        protected override BfvContextService GetContext() => _context;
        protected override EvaluatorService GetEvaluator() => _evaluator;
        protected override KeyPair GetKeyPair() => _keyPair;
    }
}