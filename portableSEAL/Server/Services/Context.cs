using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Research.SEAL;
using portableSEAL.Services;
using Server.Utils;
using static Server.Services.ContextParametersHolder;
using static Server.Utils.Util;
using static Server.Utils.Serializer;

namespace Server.Services
{
    public class BfvContextService : BfvContext.BfvContextBase
    {
        #region Instance

        public override Task<ContextId> Create(ContextParameters request, ServerCallContext context) => SafeRun(() =>
        {
            var degree = request.PolyModulusDegree;
            var coeffModulus = request.CoeffModulus == null || request.CoeffModulus.Count == 0
                ? CoeffModulus.BFVDefault(request.PolyModulusDegree)
                : CoeffModulus.Create(degree, request.CoeffModulus.AsEnumerable());

            var plainModulus = request.PlainModulusCase switch
            {
                ContextParameters.PlainModulusOneofCase.PlainModulusNumber
                => new SmallModulus(request.PlainModulusNumber),
                ContextParameters.PlainModulusOneofCase.PlainModulusBitSize
                => PlainModulus.Batching(degree, request.PlainModulusBitSize),
                ContextParameters.PlainModulusOneofCase.None
                => throw NewRpcException(StatusCode.InvalidArgument, "must provide PlainModulus(Data/BitSize)"),
                _ => throw new ArgumentOutOfRangeException()
            };

            var paras = new EncryptionParameters(SchemeType.BFV)
                {PolyModulusDegree = degree, CoeffModulus = coeffModulus, PlainModulus = plainModulus};

            ContextParametersStream = new MemoryStream((int) paras.SaveSize(CompressionMode));
            paras.Save(ContextParametersStream,
                CompressionMode); // TODO: DEFLATE or not? note that gRPC provide compression as well.
            ContextParametersStream.Position = 0;
            Context = new SEALContext(paras);
            Encoder = new IntegerEncoder(Context);

            return new ContextId {HashCode = paras.GetHashCode()}; // be careful when use GetHashCode...
        });


        public override Task<ContextId> Restore(SerializedContext request, ServerCallContext context) => SafeRun(() =>
        {
            var paras = new EncryptionParameters(SchemeType.BFV);
            var stream = ToByteMemoryStream(request.Data);
            ContextParametersStream = stream;
            paras.Load(stream);
            Context = new SEALContext(paras);
            return new ContextId {HashCode = paras.GetHashCode()};
        });


        public override Task<SerializedContext> Export(Nothing request, ServerCallContext context) => SafeRun(() =>
        {
            AssertContext("Export");
            return new SerializedContext {Data = ToByteString(ContextParametersStream)};
        });

        public static void Clear()
        {
            Plaintexts.Clear();
            Ciphertexts.Clear();
            KeyPairs.Clear();
        }

        public override Task<Nothing> Clear(Nothing request, ServerCallContext context) => SafeRunNothing(Clear);

        #endregion

        #region Cryptography

        public override Task<SerializedCiphertext> Encrypt(EncryptionNecessity request, ServerCallContext context)
        {
            AssertContext();
            var pk = new PublicKey();
            switch (request.PublicKeyCase)
            {
                case EncryptionNecessity.PublicKeyOneofCase.PublicKeyBytes:
                    pk.Load(Context, ToByteMemoryStream(request.PublicKeyBytes));
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.PublicKeyId:
                    pk = GetOrThrow("PublicKeyId", KeyPairs, request.PublicKeyId.HashCode).PublicKey;
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.None:
                    throw NewRpcException(StatusCode.InvalidArgument, "require PublicKey(Bytes/Id)");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return SafeRunAsync(async () =>
            {
                var ptId = request.PlaintextCase switch
                {
                    EncryptionNecessity.PlaintextOneofCase.PlaintextData =>
                    await MakePlaintext(request.PlaintextData, context),
                    EncryptionNecessity.PlaintextOneofCase.PlaintextId =>
                    request.PlaintextId,
                    EncryptionNecessity.PlaintextOneofCase.None =>
                    throw NewRpcException(StatusCode.InvalidArgument, "require Plaintext(Data/Id)"),
                    _ => throw new ArgumentOutOfRangeException()
                };

                var ct = new Ciphertext(Context);
                new Encryptor(Context, pk).Encrypt(Plaintexts[ptId.HashCode], ct);

                return SerializeCiphertext(ct);
            });
        }

        public override Task<DecryptionResult> Decrypt(DecryptionNecessity request, ServerCallContext context)
        {
            AssertContext();
            var sk = new SecretKey();
            switch (request.SecretKeyCase)
            {
                case DecryptionNecessity.SecretKeyOneofCase.SecretKeyBytes:
                    sk.Load(Context, ToByteMemoryStream(request.SecretKeyBytes));
                    break;
                case DecryptionNecessity.SecretKeyOneofCase.SecretKeyId:
                    sk = GetOrThrow("SecretKeyId", KeyPairs, request.SecretKeyId.HashCode).SecretKey;
                    break;
                case DecryptionNecessity.SecretKeyOneofCase.None:
                    throw NewRpcException(StatusCode.InvalidArgument, "require SecretKey(Bytes/Id)");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return SafeRunAsync(async () =>
            {
                var ctId = request.CiphertextCase switch
                {
                    DecryptionNecessity.CiphertextOneofCase.SerializedCiphertext =>
                    await ParseCiphertext(request.SerializedCiphertext, context),
                    DecryptionNecessity.CiphertextOneofCase.CiphertextId =>
                    request.CiphertextId,
                    DecryptionNecessity.CiphertextOneofCase.None =>
                    throw NewRpcException(StatusCode.InvalidArgument, "require Ciphertext(Serialized/Id)"),
                    _ => throw new ArgumentOutOfRangeException()
                };
                var ct = GetCiphertext(ctId);
                var p = new Plaintext();
                var decryptor = new Decryptor(Context, sk);
                var noiseBudget = decryptor.InvariantNoiseBudget(ct);
                if (noiseBudget <= 0)
                    throw NewRpcException(StatusCode.DataLoss,
                        $"zero noise budget indicates corrupted data. current noise budget: {noiseBudget}");
                decryptor.Decrypt(ct, p);
                return new DecryptionResult
                {
                    Plaintext = new PlaintextData {Data = Encoder.DecodeInt64(p)},
                    NoiseBudget = noiseBudget
                };
            });
        }

        #endregion

        #region Generator

        public static Task<CiphertextId> ParseCiphertext(SerializedCiphertext sc) => SafeRun(() =>
        {
            AssertContext();
            var ct = DeserializeCiphertext(Context, sc.Data);
            var hash = ct.GetHashCode();
            Ciphertexts[hash] = ct;
            return new CiphertextId {HashCode = hash};
        });

        public override Task<CiphertextId> ParseCiphertext(SerializedCiphertext request, ServerCallContext context) =>
            ParseCiphertext(request);

        public override Task<PlaintextId> MakePlaintext(PlaintextData request, ServerCallContext context) =>
            SafeRun(() =>
            {
                AssertContext();
                var p = Encoder.Encode(request.Data);
                var id = p.GetHashCode();
                Plaintexts[id] = p;
                return new PlaintextId {HashCode = id};
            });

        public override Task<KeyPair> KeyGen(Nothing request, ServerCallContext context) => SafeRun(() =>
        {
            AssertContext();
            var kp = new KeyGenerator(Context);
            var hash = kp.GetHashCode();
            KeyPairs[hash] = kp;
            var kpId = new KeyPairId {HashCode = hash};

            var pkStream = new MemoryStream((int) kp.PublicKey.SaveSize(CompressionMode));
            kp.PublicKey.Save(pkStream, CompressionMode);
            pkStream.Position = 0;

            var skStream = new MemoryStream((int) kp.SecretKey.SaveSize(CompressionMode));
            kp.SecretKey.Save(skStream, CompressionMode);
            skStream.Position = 0;

            return new KeyPair {Id = kpId, PublicKey = ToByteString(pkStream), SecretKey = ToByteString(skStream)};
        });

        #endregion

        private static void AssertContext(string operation = "access")
        {
            if (Context == null || ContextParametersStream == null || Encoder == null)
                throw NewRpcException(StatusCode.FailedPrecondition,
                    $"cannot {operation} BfvContext before Restore or Create one. try to Create or Restore first");
        }

        internal static SEALContext GetContext() => Context;
        internal static IntegerEncoder GetIntegerEncoder() => Encoder;
        internal static Ciphertext GetCiphertext(CiphertextId id) => Ciphertexts[id.HashCode];
        internal static Plaintext GetPlaintext(PlaintextId id) => Plaintexts[id.HashCode];

        private const ComprModeType CompressionMode = Serializer.CompressionMode;
        private readonly ILogger<BfvContextService> _logger;
        public BfvContextService(ILogger<BfvContextService> logger) => _logger = logger;
    }

    internal static class ContextParametersHolder
    {
        internal static SEALContext Context;
        internal static Stream ContextParametersStream;
        internal static IntegerEncoder Encoder;

        internal static readonly Dictionary<int, Ciphertext> Ciphertexts = new Dictionary<int, Ciphertext>();
        internal static readonly Dictionary<int, Plaintext> Plaintexts = new Dictionary<int, Plaintext>();
        internal static readonly Dictionary<int, KeyGenerator> KeyPairs = new Dictionary<int, KeyGenerator>();
    }
}