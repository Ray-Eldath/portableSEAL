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

        protected Task<long> EvaluatorCurrentPlain
            (bool showNoiseBudget = true, bool showPlainData = true, string header = "") => Task.Run(async () =>
        {
            var r = await GetContext().Decrypt(
                new DecryptionNecessity
                {
                    SerializedCiphertext = await GetEvaluator().Current(_nothing, _mockContext),
                    SecretKeyId = GetKeyPair().Id
                }, _mockContext);
            if (showNoiseBudget)
                Console.WriteLine("plaintext noise budget: {0}", r.NoiseBudget);
            var rp = r.Plaintext.Data;
            var h = header == "" ? "" : header + ": ";
            if (showPlainData)
                Console.WriteLine("{0}EvaluatorCurrentPlain: {1}", h, rp);
            return rp;
        });

        protected Task<SerializedCiphertext> CreateEvaluator
            (long initial, bool createEvaluator = true) => Task.Run(async () =>
        {
            var ct = await GetContext().Encrypt(
                new EncryptionNecessity
                {
                    PlaintextData = new PlaintextData {Data = initial},
                    PublicKeyId = GetKeyPair().Id
                }, _mockContext);
            if (!createEvaluator) return ct;

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