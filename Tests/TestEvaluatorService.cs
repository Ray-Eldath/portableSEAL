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

        [Test]
        public void TestAdd(
            [Random(SafeMin, SafeMax, 2)] [Values(0L, -11030213L)]
            long a,
            [Random(SafeMin, SafeMax, 2)] [Values(0L, 11030213L)]
            long b) => Assert.DoesNotThrowAsync(async () =>
        {
            await CreateEvaluator(a);
            Console.WriteLine("add {0} to {1}", a, b);
            await _evaluator.Add(new BinaryOperand {PlaintextData = new PlaintextData {Data = b}}, _mockContext);
            Assert.AreEqual(a + b, await EvaluatorCurrentPlain());
        });

        [Test]
        public void TestCreateAndCurrent(
            [Random(SafeMin, SafeMax, 3)] [Values(0L, -1103L, 1103L)]
            long initial) => Assert.DoesNotThrowAsync(async () =>
        {
            await CreateEvaluator(initial);
            var r = await EvaluatorCurrentPlain();
            Assert.AreEqual(initial, r);
        });

        private Task CreateEvaluator(long initial) => Task.Run(async () =>
        {
            var ct = await _context.Encrypt(
                new EncryptionNecessity
                {
                    PlaintextData = new PlaintextData {Data = initial},
                    PublicKeyId = _keyPair.Id
                }, _mockContext);

            await _evaluator.Create(await _context.ParseCiphertext(ct, _mockContext), _mockContext);
            Console.WriteLine("---evaluator created");
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

        private readonly Nothing _nothing = new Nothing();
        private const long SafeMin = int.MinValue, SafeMax = int.MaxValue;

        [TearDown]
        public void TearDownTest() => _context.Destroy(_nothing, _mockContext);

        [SetUp]
        public void SetUpTest() => Assert.DoesNotThrowAsync(async () =>
        {
            await _context.Create(new ContextParameters {PlainModulus = 512, PolyModulusDegree = 2048}, _mockContext);
            _keyPair = await _context.KeyGen(_nothing, _mockContext);
            Console.WriteLine("---context created");
        });
    }
}