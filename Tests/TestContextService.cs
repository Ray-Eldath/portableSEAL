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
            });

        [Test]
        public void TestExportAndRestore() =>
            Task.Run(async () =>
            {
                var serialized = await _service.Export(_nothing, _mockContext);
                var deserialized = await _service.Restore(serialized, _mockContext);
                Assert.AreEqual(_contextId, deserialized.HashCode);
            });

        [Test]
        public void TestDestroy() =>
            Assert.DoesNotThrow(() => { _service.Destroy(_nothing, _mockContext); });

        [Test]
        public void TestKeyGen() =>
            Assert.DoesNotThrowAsync(async () => { _keyPair = await _service.KeyGen(_nothing, _mockContext); });

        [Test]
        [TestCaseSource(nameof(MockData.LongSource))]
        public void TestMakePlaintext(long data) =>
            Assert.DoesNotThrowAsync(async () =>
            {
                await _service.MakePlaintext(new PlaintextData() {Data = data}, _mockContext);
            });

        [SetUp]
        public void SetUpTest()
        {
            TestCreate();
            TestKeyGen();
        }
    }
}