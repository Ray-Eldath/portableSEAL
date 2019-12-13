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
using static Server.Utils.Util;
using static Server.Utils.Serializer;

namespace Server.Services
{
    public class BfvContextService : BfvContext.BfvContextBase
    {
        private static SEALContext _context;
        private static IntegerEncoder _encoder;
        private Stream _contextParameters;

        private static readonly Dictionary<int, Ciphertext> CiphertextMap = new Dictionary<int, Ciphertext>();
        private static readonly Dictionary<int, Plaintext> PlaintextMap = new Dictionary<int, Plaintext>();
        private readonly Dictionary<int, KeyGenerator> _keyPairMap = new Dictionary<int, KeyGenerator>();

        public override Task<ContextId> Create(ContextParameters request, ServerCallContext context) => Task.Run(() =>
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

            _contextParameters =
                new MemoryStream((int) paras.SaveSize(CompressionMode)); // TODO: check if bigger than Int.MAX
            paras.Save(_contextParameters,
                CompressionMode); // TODO: DEFLATE or not? note that gRPC provide compression as well.
            _contextParameters.Position = 0;
            _context = new SEALContext(paras);
            _encoder = new IntegerEncoder(_context);

            return new ContextId {HashCode = paras.GetHashCode()}; // be careful when use GetHashCode...
        });


        public override Task<ContextId> Restore(SerializedContext request, ServerCallContext context) => Task.Run(() =>
        {
            var paras = new EncryptionParameters(SchemeType.BFV);
            var stream = ToByteMemoryStream(request.Data);
            _contextParameters = stream;
            paras.Load(stream);
            _context = new SEALContext(paras);
            return new ContextId {HashCode = paras.GetHashCode()};
        });


        public override Task<SerializedContext> Export(Nothing request, ServerCallContext context) => Task.Run(() =>
        {
            AssertContext("Export");
            return new SerializedContext {Data = ToByteString(_contextParameters)};
        });

        public override Task<Nothing> Destroy(Nothing request, ServerCallContext context) => RunNothing(() =>
        {
            PlaintextMap.Clear();
            CiphertextMap.Clear();
            _keyPairMap.Clear();
            _context = null;
        });

        ////////

        public override Task<SerializedCiphertext> Encrypt(EncryptionNecessity request, ServerCallContext context)
        {
            AssertContext();
            var pk = new PublicKey();
            switch (request.PublicKeyCase)
            {
                case EncryptionNecessity.PublicKeyOneofCase.PublicKeyBytes:
                    pk.Load(_context, ToByteMemoryStream(request.PublicKeyBytes));
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.PublicKeyId:
                    pk = GetOrThrow("PublicKeyId", _keyPairMap, request.PublicKeyId.HashCode).PublicKey;
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.None:
                    throw NewRpcException(StatusCode.InvalidArgument, "require PublicKey(Bytes/Id)");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return Task.Run(async () =>
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

                var ct = new Ciphertext(_context);
                new Encryptor(_context, pk).Encrypt(PlaintextMap[ptId.HashCode], ct);

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
                    sk.Load(_context, ToByteMemoryStream(request.SecretKeyBytes));
                    break;
                case DecryptionNecessity.SecretKeyOneofCase.SecretKeyId:
                    sk = GetOrThrow("SecretKeyId", _keyPairMap, request.SecretKeyId.HashCode).SecretKey;
                    break;
                case DecryptionNecessity.SecretKeyOneofCase.None:
                    throw NewRpcException(StatusCode.InvalidArgument, "require SecretKey(Bytes/Id)");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return Task.Run(async () =>
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
                var decryptor = new Decryptor(_context, sk);
                var noiseBudget = decryptor.InvariantNoiseBudget(ct);
                if (noiseBudget <= 0)
                    throw NewRpcException(StatusCode.DataLoss,
                        $"zero noise budget indicates corrupted data. current noise budget: {noiseBudget}");
                decryptor.Decrypt(ct, p);
                return new DecryptionResult
                {
                    Plaintext = new PlaintextData {Data = _encoder.DecodeInt64(p)},
                    NoiseBudget = noiseBudget
                };
            });
        }

        ////////

        public override Task<CiphertextId> ParseCiphertext(SerializedCiphertext request, ServerCallContext context) =>
            Task.Run(() =>
            {
                AssertContext();
                var ct = DeserializeCiphertext(_context, request.Data);
                var hash = ct.GetHashCode();
                CiphertextMap[hash] = ct;
                return new CiphertextId {HashCode = hash};
            });

        public override Task<PlaintextId> MakePlaintext(PlaintextData request, ServerCallContext context) =>
            Task.Run(() =>
            {
                AssertContext();
                var p = _encoder.Encode(request.Data);
                var id = p.GetHashCode();
                PlaintextMap[id] = p;
                return new PlaintextId {HashCode = id};
            });

        ////////

        public override Task<KeyPair> KeyGen(Nothing request, ServerCallContext context) => Task.Run(() =>
        {
            AssertContext();
            var kp = new KeyGenerator(_context);
            var hash = kp.GetHashCode();
            _keyPairMap[hash] = kp;
            var kpId = new KeyPairId {HashCode = hash};

            var pkStream = new MemoryStream((int) kp.PublicKey.SaveSize(CompressionMode));
            kp.PublicKey.Save(pkStream, CompressionMode);
            pkStream.Position = 0;

            var skStream = new MemoryStream((int) kp.SecretKey.SaveSize(CompressionMode));
            kp.SecretKey.Save(skStream, CompressionMode);
            skStream.Position = 0;

            return new KeyPair {Id = kpId, PublicKey = ToByteString(pkStream), SecretKey = ToByteString(skStream)};
        });

        private void AssertContext(string operation = "access")
        {
            if (_context == null || _contextParameters == null || _encoder == null)
                throw NewRpcException(StatusCode.FailedPrecondition,
                    $"cannot {operation} BfvContext before Restore or Create one. try to Create or Restore first");
        }

        internal static SEALContext GetContext() => _context;
        internal static IntegerEncoder GetIntegerEncoder() => _encoder;
        internal static Ciphertext GetCiphertext(CiphertextId id) => CiphertextMap[id.HashCode];
        internal static Plaintext GetPlaintext(PlaintextId id) => PlaintextMap[id.HashCode];

        private const ComprModeType CompressionMode = Serializer.CompressionMode;
        private readonly ILogger<BfvContextService> _logger;
        public BfvContextService(ILogger<BfvContextService> logger) => _logger = logger;
    }
}