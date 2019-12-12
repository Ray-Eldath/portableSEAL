using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using portableSEAL.Services;
using Server.Services;
using Tests.Helpers;

namespace Tests
{
    [ExcludeFromCodeCoverage]
    [Author("Ray Eldath")]
    [TestFixture(TestName = "test arithmetical operations")]
    public class TestEvaluatorService
    {
        private ServerCallContext _mockContext = MockServerCallContext.Create();
        private EvaluatorService _evaluator = new EvaluatorService(new NullLogger<EvaluatorService>());
        private ContextService _context = new ContextService(new NullLogger<ContextService>());
        private KeyPair _keyPair;

        [Test, Description("test polynomial r( x^2 + x + 4 )")]
        public void TestRelinearizedPolynomial(
            [Random(SafeMin, SafeMax, 2)] long l) => Assert.DoesNotThrowAsync(async () =>
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
            await _evaluator.Relinearize(_nothing, _mockContext);
            Assert.AreEqual(expected, a);
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

        private Task<SerializedCiphertext> CreateEvaluator(long initial) => Task.Run(async () =>
        {
            var ct = await _context.Encrypt(
                new EncryptionNecessity
                {
                    PlaintextData = new PlaintextData {Data = initial},
                    PublicKeyId = _keyPair.Id
                }, _mockContext);

            await _evaluator.Create(await _context.ParseCiphertext(ct, _mockContext), _mockContext);
            Console.WriteLine("---evaluator created");
            return ct;
        });

        private Task<long> EvaluatorCurrentPlain() => Task.Run(async () =>
            {
                var r = await _context.Decrypt(
                    new DecryptionNecessity
                    {
                        SerializedCiphertext = await _evaluator.Current(_nothing, _mockContext),
                        SecretKeyId = _keyPair.Id
                    }, _mockContext);
                Console.WriteLine("plaintext noise budget: {0}", r.NoiseBudget);
                var rp = r.Plaintext.Data;
                Console.WriteLine("EvaluatorCurrentPlain: {0}", rp);
                return rp;
            }
        );

        private BinaryOperand NewPlaintextData(long d) =>
            new BinaryOperand {PlaintextData = new PlaintextData {Data = d}};

        private BinaryOperand NewSerializedCiphertext(SerializedCiphertext ct) =>
            new BinaryOperand {SerializedCiphertext = ct};

        private readonly Nothing _nothing = new Nothing();
        private const long Min = long.MinValue, Max = long.MaxValue, SafeMin = int.MinValue, SafeMax = int.MaxValue;

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
    }
}