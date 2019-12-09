using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using portableSEAL.Services;
using Server.Services;
using Tests.Helpers;

namespace Tests
{
    [Author("Ray Eldath")]
    [TestFixture(TestName = "test SEALContext operations of SEAL")]
    public class TestContextService
    {
        private ServerCallContext _mockContext = MockServerCallContext.Create();
        private Nothing _nothing = new Nothing();
        private ContextService _service = new ContextService(new NullLogger<ContextService>());

        [Test]
        [SetUp]
        public void TestCreate() =>
            Assert.DoesNotThrowAsync(async () =>
                await _service.Create(new ContextParameters()
                {
                    PlainModulus = 1024,
                    PolyModulusDegree = 4096
                }, _mockContext));

        [Test]
        [Order(1)]
        public void TestExportAndRestore() =>
            Assert.DoesNotThrowAsync(async () =>
            {
                var serialized = await _service.Export(_nothing, _mockContext);
                await _service.Restore(serialized, _mockContext);
            });
    }
}