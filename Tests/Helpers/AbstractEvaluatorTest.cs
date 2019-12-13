using System;
using System.Threading.Tasks;
using portableSEAL.Services;
using Server.Services;
using static Tests.Helpers.Constants;

namespace Tests.Helpers
{
    public abstract class AbstractEvaluatorTest
    {
        protected abstract BfvContextService GetContext();
        protected abstract EvaluatorService GetEvaluator();
        protected abstract KeyPair GetKeyPair();

        protected Task<long> EvaluatorCurrentPlain(bool showNoiseBudgetOnly = false) => Task.Run(async () =>
        {
            var r = await GetContext().Decrypt(
                new DecryptionNecessity
                {
                    SerializedCiphertext = await GetEvaluator().Current(_nothing, _mockContext),
                    SecretKeyId = GetKeyPair().Id
                }, _mockContext);
            Console.WriteLine("plaintext noise budget: {0}", r.NoiseBudget);
            var rp = r.Plaintext.Data;
            if (!showNoiseBudgetOnly)
                Console.WriteLine("EvaluatorCurrentPlain: {0}", rp);
            return rp;
        });

        protected Task<SerializedCiphertext> CreateEvaluator(long initial) => Task.Run(async () =>
        {
            var ct = await GetContext().Encrypt(
                new EncryptionNecessity
                {
                    PlaintextData = new PlaintextData {Data = initial},
                    PublicKeyId = GetKeyPair().Id
                }, _mockContext);

            await GetEvaluator().Create(await GetContext().ParseCiphertext(ct, _mockContext),
                _mockContext); // TODO: combine two operation into a new operation maybe...?
            Console.WriteLine("---evaluator created");
            return ct;
        });

        protected static BinaryOperand NewPlaintextData(long d) =>
            new BinaryOperand {PlaintextData = new PlaintextData {Data = d}};

        protected static BinaryOperand NewSerializedCiphertext(SerializedCiphertext ct) =>
            new BinaryOperand {SerializedCiphertext = ct};
    }
}