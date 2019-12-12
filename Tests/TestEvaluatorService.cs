using System.Diagnostics.CodeAnalysis;
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
        private long _initial;

        private Nothing _nothing = new Nothing();

        [Test]
        public void TestAdd(
            [Random(SafeMin, SafeMax, 5)] [Values(0L, -1103L, 1103L)]
            long b) => Assert.DoesNotThrow(() =>
        {
            _evaluator.Add(new BinaryOperand {PlaintextData = new PlaintextData {Data = b}}, _mockContext);
            // var ct = await _context.Encrypt(new EncryptionNecessity() {})
        });

        [Test]
        public void TestCreateAndResult(
            [Random(SafeMin, SafeMax, 5)] [Values(0L, -1103L, 1103L)]
            long initial) => Assert.DoesNotThrowAsync(async () =>
        {
            _initial = initial;
            var ct = await _context.Encrypt(
                new EncryptionNecessity
                {
                    PlaintextData = new PlaintextData {Data = initial},
                    PublicKeyId = _keyPair.Id
                }, _mockContext);

            await _evaluator.Create(await _context.ParseCiphertext(ct, _mockContext), _mockContext);
            var r = await _context.Decrypt(
                new DecryptionNecessity
                {
                    SerializedCiphertext = await _evaluator.Result(_nothing, _mockContext),
                    SecretKeyId = _keyPair.Id
                }, _mockContext);
            Assert.AreEqual(_initial, r.Data);
        });

        private const long SafeMin = int.MinValue, SafeMax = int.MaxValue;

        [SetUp]
        public void SetUpTest() => Assert.DoesNotThrowAsync(async () =>
        {
            await _context.Create(new ContextParameters {PlainModulus = 1024, PolyModulusDegree = 4096}, _mockContext);
            _keyPair = await _context.KeyGen(_nothing, _mockContext);
        });
    }
}