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
    // TODO: 参数校验：oneof 检查 None；检查 _context 是否初始化等

    public class ContextService : Context.ContextBase
    {
        private static SEALContext _context;
        private static IntegerEncoder _encoder;
        private Stream _contextParameters;

        private static Dictionary<int, Ciphertext> _ciphertextMap = new Dictionary<int, Ciphertext>();
        private static Dictionary<int, Plaintext> _plaintextMap = new Dictionary<int, Plaintext>();
        private Dictionary<int, KeyGenerator> _keyPairMap = new Dictionary<int, KeyGenerator>();

        public override Task<ContextId> Create(ContextParameters request, ServerCallContext context) => Task.Run(() =>
        {
            var coeffModulus = request.CoeffModulus.Count == 0
                ? CoeffModulus.BFVDefault(request.PolyModulusDegree)
                : request.CoeffModulus.Select(e => new SmallModulus(e));

            var paras = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = request.PolyModulusDegree,
                CoeffModulus = coeffModulus,
                PlainModulus = new SmallModulus(request.PlainModulus)
            };
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
            new SerializedContext {Data = ToByteString(_contextParameters)});

        public override Task<Nothing> Destroy(Nothing request, ServerCallContext context) => RunNothing(() =>
        {
            _plaintextMap.Clear();
            _ciphertextMap.Clear();
            _keyPairMap.Clear();
            _context = null;
        });

        ////////

        public override Task<SerializedCiphertext> Encrypt(EncryptionNecessity request, ServerCallContext context)
        {
            var pk = new PublicKey();
            switch (request.PublicKeyCase)
            {
                case EncryptionNecessity.PublicKeyOneofCase.PublicKeyBytes:
                    pk.Load(_context, ToByteMemoryStream(request.PublicKeyBytes));
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.PublicKeyId:
                    pk = _keyPairMap[request.PublicKeyId.HashCode].PublicKey;
                    break;
                default:
                    // TODO
                    throw new ArgumentOutOfRangeException();
            }

            return Task.Run(() =>
            {
                var ct = new Ciphertext(_context);
                new Encryptor(_context, pk).Encrypt(_plaintextMap[request.PlaintextId.HashCode], ct);

                return SerializeCiphertext(ct);
            });
        }

        public override Task<PlaintextData> Decrypt(DecryptionNecessity request, ServerCallContext context)
        {
            var ct = _ciphertextMap[request.CiphertextId.HashCode];
            var sk = new SecretKey();
            switch (request.SecretKeyCase)
            {
                case DecryptionNecessity.SecretKeyOneofCase.SecretKeyBytes:
                    sk.Load(_context, ToByteMemoryStream(request.SecretKeyBytes));
                    break;
                case DecryptionNecessity.SecretKeyOneofCase.SecretKeyId:
                    sk = _keyPairMap[request.SecretKeyId.HashCode].SecretKey;
                    break;
                default:
                    // TODO
                    throw new ArgumentOutOfRangeException();
            }

            return Task.Run(() =>
            {
                var p = new Plaintext();
                var decryptor = new Decryptor(_context, sk);
                if (decryptor.InvariantNoiseBudget(ct) == 0)
                    throw NewRpcException(StatusCode.DataLoss, "zero noise budget indicates corrupted data");
                decryptor.Decrypt(ct, p);
                return new PlaintextData {Data = _encoder.DecodeInt64(p)};
            });
        }

        ////////

        public override Task<CiphertextId> ParseCiphertext(SerializedCiphertext request, ServerCallContext context) =>
            Task.Run(() =>
            {
                var ct = DeserializeCiphertext(_context, request.Data);
                var hash = ct.GetHashCode();
                _ciphertextMap[hash] = ct;
                return new CiphertextId {HashCode = hash};
            });

        public override Task<PlaintextId> MakePlaintext(PlaintextData request, ServerCallContext context) =>
            Task.Run(() =>
            {
                var p = _encoder.Encode(request.Data);
                var id = p.GetHashCode();
                _plaintextMap[id] = p;
                return new PlaintextId {HashCode = id};
            });

        ////////

        public override Task<KeyPair> KeyGen(Nothing request, ServerCallContext context) => Task.Run(() =>
        {
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

        internal static SEALContext GetContext() => _context;
        internal static IntegerEncoder GetIntegerEncoder() => _encoder;
        internal static Ciphertext GetCiphertext(CiphertextId id) => _ciphertextMap[id.HashCode];
        internal static Plaintext GetPlaintext(PlaintextId id) => _plaintextMap[id.HashCode];

        private const ComprModeType CompressionMode = Serializer.CompressionMode;
        private readonly ILogger<ContextService> _logger;
        public ContextService(ILogger<ContextService> logger) => _logger = logger;
    }
}