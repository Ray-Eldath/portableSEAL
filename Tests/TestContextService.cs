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
    [TestFixture(TestName = "test SEALContext operations")]
    public class TestContextService
    {
        private ServerCallContext _mockContext = MockServerCallContext.Create();
        private ContextService _service = new ContextService(new NullLogger<ContextService>());

        private Nothing _nothing = new Nothing();

        private int _contextId;
        private KeyPair _keyPair;

        [Test]
        public void TestCreate() =>
            Assert.DoesNotThrowAsync(async () =>
            {
                _contextId = (await _service.Create(new ContextParameters()
                {
                    PlainModulus = 1024,
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
            [Random(Min + 1, Max - 1, 5)] [Values(0L, Min, Max)]
            long data) =>
            Assert.DoesNotThrow(() =>
            {
                var id = _service.MakePlaintext(new PlaintextData {Data = data}, _mockContext);
                Console.WriteLine("plaintextId: {0}", id.Result.HashCode);
            });

        [Test]
        public Task TestEncryptAndDecrypt(
            [Random(Min + 1, Max - 1, 5)] [Values(0L, Min, Max)]
            long data) => Task.Run(async () =>
        {
            var plaintext = await _service.MakePlaintext(new PlaintextData {Data = data}, _mockContext);
            var ciphertextData =
                await _service.Encrypt(new EncryptionNecessity
                    {PlaintextId = plaintext, PublicKeyId = _keyPair.Id}, _mockContext);
            Console.WriteLine("plaintext: {0}", plaintext);

            var ciphertext = await _service.ParseCiphertext(ciphertextData, _mockContext);
            Console.WriteLine("ciphertext: {0}", ciphertext);

            var p2 =
                await _service.Decrypt(new DecryptionNecessity
                    {CiphertextId = ciphertext, SecretKeyId = _keyPair.Id}, _mockContext);
            Console.WriteLine("plaintext #2: {0}", p2.Data);

            Assert.AreEqual(p2.Data, data);
        });

        private const long Min = long.MinValue;
        private const long Max = long.MaxValue;

        [SetUp]
        public void SetUpTest()
        {
            TestCreate();
            TestKeyGen();
        }
    }
}