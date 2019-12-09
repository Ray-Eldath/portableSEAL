using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using portableSEAL.Services;
using Server.Services;
using Tests.Helpers;

namespace Tests
{
    [Author("Ray Eldath")]
    [TestFixture(TestName = "test SEALContext operations")]
    public class TestContextService
    {
        private ServerCallContext _mockContext = MockServerCallContext.Create();
        private Nothing _nothing = new Nothing();
        private ContextService _service = new ContextService(new NullLogger<ContextService>());

        private int _contextId = 0;

        [Test]
        [SetUp]
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
        [Order(1)]
        public void TestExportAndRestore() =>
            Task.Run(async () =>
            {
                var serialized = await _service.Export(_nothing, _mockContext);
                var deserialized = await _service.Restore(serialized, _mockContext);
                Assert.AreEqual(_contextId, deserialized.HashCode);
            });
    }
}