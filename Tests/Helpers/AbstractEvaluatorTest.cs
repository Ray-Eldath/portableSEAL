﻿using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using portableSEAL.Services;
using Server.Services;
using static Server.Utils.Util;
using static Tests.Helpers.Constants;

namespace Tests.Helpers
{
    [ExcludeFromCodeCoverage]
    public abstract class AbstractEvaluatorTest
    {
        protected abstract BfvContextService GetContext();
        protected abstract EvaluatorService GetEvaluator();
        protected abstract KeyPair GetKeyPair();

        protected Task<long> EvaluatorCurrentPlain
            (bool showNoiseBudget = true, bool showPlainData = true, string header = "") => Task.Run(async () =>
        {
            var ct = await GetEvaluator().Current(_nothing, _mockContext);
            var r = await GetContext().Decrypt(
                new DecryptionNecessity
                {
                    SerializedCiphertext = ct,
                    SecretKeyId = GetKeyPair().Id
                }, _mockContext);
            if (header != "")
                Console.WriteLine($"-{header}: ");
            if (showNoiseBudget)
                Console.WriteLine("plaintext noise budget: {0}", r.NoiseBudget);
            var rp = r.Plaintext.Data;
            if (showPlainData)
                Console.WriteLine("EvaluatorCurrentPlain: {0, -23}||  ciphertext size: {1}",
                    rp, ToSizeString(ct.CalculateSize()));
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