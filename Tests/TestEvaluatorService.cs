using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using portableSEAL.Services;
using Server.Services;
using Tests.Helpers;
using static Tests.Helpers.Constants;

namespace Tests
{
    [ExcludeFromCodeCoverage]
    [Author("Ray Eldath")]
    [TestFixture(TestName = "test arithmetical operations")]
    public class TestEvaluatorService : AbstractEvaluatorTest
    {
        private readonly EvaluatorService _evaluator = new EvaluatorService(new NullLogger<EvaluatorService>());
        private readonly BfvContextService _context = new BfvContextService(new NullLogger<BfvContextService>());
        private KeyPair _keyPair;

        [Test, Description("evaluate \"straight\" polynomial r( x^2 + x + 4 )")]
        public void TestRelinearizedStraightPolynomial(
            [Random(SafeMin, SafeMax, 3)] long l) => Assert.DoesNotThrowAsync(async () =>
        {
            await _context.Create(new ContextParameters
            {
                PlainModulusNumber = 512,
                PolyModulusDegree = 4096,
                CoeffModulus = {50, 50}
            }, _mockContext);
            //
            _keyPair = await _context.KeyGen(_nothing, _mockContext);
            var expected = l * l + l + 4L;
            Console.WriteLine("r( {0}^2 + {0} + 4 ): should be {1}", l, expected);

            var ct = await CreateEvaluator(l);
            await EvaluatorCurrentPlain();

            await _evaluator.Square(_nothing, _mockContext);
            await _evaluator.Add(NewSerializedCiphertext(ct), _mockContext);
            await _evaluator.Add(NewPlaintextData(4L), _mockContext);

            var a = await EvaluatorCurrentPlain(); // show noise budget
            await CreateEvaluator(a);
            Console.Write("after r: ");
            await _evaluator.Relinearize(_nothing, _mockContext);
            var aa = await EvaluatorCurrentPlain();
            Assert.AreEqual(expected, aa);
        });

        [Test]
        public void TestNegate([Random(Min, Max, 1)] [Values(0, 1L, -1L)]
            long l) => Assert.DoesNotThrowAsync(async () =>
        {
            Console.WriteLine("-({0}): should be {1}", l, -l);
            await CreateEvaluator(l);
            await _evaluator.Negate(_nothing, _mockContext);
            Assert.AreEqual(-l, await EvaluatorCurrentPlain());
        });

        [Test]
        public void TestMultiply(
            [Random(SafeMin, SafeMax, 2)] [Values(1L, -1L)] // X * 0 will cause InvalidOperationException
            long a,
            [Random(SafeMin, SafeMax, 2)] [Values(1L, -1L)]
            long b) => Assert.DoesNotThrowAsync(async () =>
            await Calculate('*', (l1, l2) => l1 * l2,
                (op, c) => _evaluator.Multiply(op, c), a, b));

        [Test]
        public void TestAdd(
            [Random(0, Max, 2)] [Values(0L, Max)] long a,
            [Random(Min, 0, 2)] [Values(Min, 0L)] long b) => Assert.DoesNotThrowAsync(async () =>
            await Calculate('+', (l1, l2) => l1 + l2,
                (op, c) => _evaluator.Add(op, c), a, b));

        [Test]
        public void TestSub(
            [Random(0, Max, 2)] [Values(0L, Max)] long a,
            [Random(0, Max, 2)] [Values(0L, Max)] long b) => Assert.DoesNotThrowAsync(async () =>
            await Calculate('-', (l1, l2) => l1 - l2,
                (op, c) => _evaluator.Sub(op, c), a, b));

        private Task Calculate(
            char op, Func<long, long, long> poly, Func<BinaryOperand, ServerCallContext, Task<Nothing>> polyFunc,
            long a, long b
        ) => Task.Run(async () =>
        {
            await CreateEvaluator(a);
            var excepted = poly.Invoke(a, b);
            Console.WriteLine(a + " " + op + " " + b + ": should be " + excepted);
            await polyFunc.Invoke(NewPlaintextData(b), _mockContext);
            Assert.AreEqual(excepted, await EvaluatorCurrentPlain());
        });

        [Test]
        public void TestCreateAndCurrent(
            [Random(Min, Max, 2)] [Values(Max, Min, 0L)]
            long initial) => Assert.DoesNotThrowAsync(async () =>
        {
            await CreateEvaluator(initial);
            var r = await EvaluatorCurrentPlain();
            Assert.AreEqual(initial, r);
        });

        //////

        [TearDown]
        public void TearDownTest() => _context.Destroy(_nothing, _mockContext);

        [SetUp]
        public void SetUpTest() => Assert.DoesNotThrowAsync(async () =>
        {
            await _context.Create(
                new ContextParameters {PlainModulusNumber = 512, PolyModulusDegree = 1024}, _mockContext);
            _keyPair = await _context.KeyGen(_nothing, _mockContext);
            Console.WriteLine("---context created");
        });

        protected override BfvContextService GetContext() => _context;
        protected override EvaluatorService GetEvaluator() => _evaluator;
        protected override KeyPair GetKeyPair() => _keyPair;
    }
}