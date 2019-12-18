using System;
using System.Diagnostics;
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
    [TestFixture(TestName = "test context operations")]
    public class TestContextService
    {
        private readonly ServerCallContext _mockContext = MockServerCallContext.Create();
        private readonly BfvContextService _service = new BfvContextService(new NullLogger<BfvContextService>());

        private int _contextId;
        private KeyPair _keyPair;

        [Test]
        public void TestCreate() =>
            Assert.DoesNotThrowAsync(async () =>
            {
                _contextId = (await _service.Create(new ContextParameters
                {
                    PlainModulusNumber = 1024,
                    PolyModulusDegree = 4096
                }, _mockContext)).HashCode;
                Console.WriteLine("contextId: {0}", _contextId);
            });

        [Test]
        public Task TestExportAndRestore() => Task.Run(async () =>
        {
            var serialized = await _service.Export(_nothing, _mockContext);
            var deserialized = await _service.Restore(serialized, _mockContext);
            Console.WriteLine("deserialized: {0}", deserialized.HashCode);
            Assert.AreEqual(_contextId, deserialized.HashCode);
        });

        [Test]
        [TearDown]
        public void TestDestroy() =>
            Assert.DoesNotThrow(() => { _service.Destroy(_nothing, _mockContext); });

        [Test]
        public void TestKeyGen() =>
            Assert.DoesNotThrowAsync(async () =>
            {
                _keyPair = await _service.KeyGen(_nothing, _mockContext);
                Console.WriteLine("keyPairId: {0}", _keyPair.Id);
            });

        [Test]
        public void TestMakePlaintext(
            [Random(Min + 1, Max - 1, 3)] [Values(0L, Min, Max)]
            long data) =>
            Assert.DoesNotThrow(() =>
            {
                var id = _service.MakePlaintext(new PlaintextData {Data = data}, _mockContext);
                Console.WriteLine("plaintextId: {0}", id.Result.HashCode);
            });

        [Test]
        public Task TestEncryptAndDecrypt(
            [Random(Min + 1, Max - 1, 3)] [Values(0L, Min, Max)]
            long data) => Task.Run(async () =>
        {
            var sw = new Stopwatch();
            sw.Start();
            var plaintext = await _service.MakePlaintext(new PlaintextData {Data = data}, _mockContext);
            Console.WriteLine("[{1,-3}ms] plaintext: {0}", plaintext, sw.ElapsedMilliseconds);

            var ciphertextData =
                await _service.Encrypt(new EncryptionNecessity
                    {PlaintextId = plaintext, PublicKeyId = _keyPair.Id}, _mockContext);

            var ciphertext = await _service.ParseCiphertext(ciphertextData, _mockContext);
            Console.WriteLine("[{1,-3}ms] ciphertext: {0}", ciphertext, sw.ElapsedMilliseconds);

            var p2 =
                await _service.Decrypt(new DecryptionNecessity
                    {CiphertextId = ciphertext, SecretKeyId = _keyPair.Id}, _mockContext);
            Console.WriteLine("plaintext #2 noise budget: {0}", p2.NoiseBudget);
            Console.WriteLine("[{1,-3}ms] plaintext #2: {0}", p2.Plaintext.Data, sw.ElapsedMilliseconds);
            sw.Stop();

            Assert.AreEqual(p2.Plaintext.Data, data);
        });

        [SetUp]
        public void SetUpTest()
        {
            TestCreate();
            TestKeyGen();
            Console.WriteLine("---context created");
        }
    }
}