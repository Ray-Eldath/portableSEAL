using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Research.SEAL;
using portableSEAL.Services;

namespace Server.Services
{
    // TODO: 参数校验：oneof 检查 None；检查 _context 是否初始化等

    public class ContextService : Context.ContextBase
    {
        private readonly ILogger<ContextService> _logger;

        private readonly Nothing _nothing = new Nothing();

        private MemoryStream _contextParameters = new MemoryStream();
        private SEALContext _context;
        private IntegerEncoder _encoder;

        private Dictionary<int, KeyGenerator> _keyPairMap = new Dictionary<int, KeyGenerator>();
        private Dictionary<int, Ciphertext> _ciphertextMap = new Dictionary<int, Ciphertext>();
        private Dictionary<int, Plaintext> _plaintextMap = new Dictionary<int, Plaintext>();

        public override Task<Nothing> Create(ContextParameters request, ServerCallContext context) =>
            Task.Run(() =>
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
                paras.Save(_contextParameters);
                _context = new SEALContext(paras);
                _encoder = new IntegerEncoder(_context);

                return _nothing;
            });


        public override Task<Nothing> Restore(SerializedContext request, ServerCallContext context) =>
            Task.Run(() =>
            {
                var paras = new EncryptionParameters(SchemeType.BFV);
                var stream = ToByteMemoryStream(request.Data);
                _contextParameters = stream;
                paras.Load(stream);
                _context = new SEALContext(paras);
                return _nothing;
            });


        public override Task<SerializedContext> Export(Nothing request, ServerCallContext context) =>
            Task.Run(() => new SerializedContext
            {
                Data = ByteString.FromStream(_contextParameters),
                Size = _contextParameters.Capacity
            });

        public override Task<Nothing> Destroy(Nothing request, ServerCallContext context)
        {
            return base.Destroy(request, context);
        }

        ////////

        public override Task<SerializedCiphertext> Encrypt(EncryptionNecessity request, ServerCallContext context)
        {
            var pk = new PublicKey();
            switch (request.PublicKeyCase)
            {
                case EncryptionNecessity.PublicKeyOneofCase.Bytes:
                    pk.Load(_context, ToByteMemoryStream(request.Bytes));
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.Id:
                    pk = _keyPairMap[request.Id.HashCode].PublicKey;
                    break;
                case EncryptionNecessity.PublicKeyOneofCase.None:
                    // TODO
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return Task.Run(() =>
            {
                var ct = new Ciphertext(_context);
                new Encryptor(_context, pk).Encrypt(_plaintextMap[request.PlaintextId.HashCode], ct);
                var r = new MemoryStream();
                ct.Save(r);
                return new SerializedCiphertext {Data = ByteString.FromStream(r), Size = r.Capacity};
            });
        }

        public override Task<PlaintextData> Decrypt(DecryptionNecessity request, ServerCallContext context)
        {
            var ct = _ciphertextMap[request.CiphertextId.HashCode];
            var sk = new SecretKey();
            switch (request.PrivateKeyCase)
            {
                case DecryptionNecessity.PrivateKeyOneofCase.Bytes:
                    sk.Load(_context, ToByteMemoryStream(request.Bytes));
                    break;
                case DecryptionNecessity.PrivateKeyOneofCase.Id:
                    sk = _keyPairMap[request.Id.HashCode].SecretKey;
                    break;
                case DecryptionNecessity.PrivateKeyOneofCase.None:
                    // TODO:
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return Task.Run(() =>
            {
                var p = new Plaintext();
                new Decryptor(_context, sk).Decrypt(ct, p);
                return new PlaintextData {Data = _encoder.DecodeInt64(p)};
            });
        }

        ////////

        public override Task<CiphertextId> ParseCiphertext(SerializedCiphertext request, ServerCallContext context) =>
            Task.Run(() =>
            {
                var ct = new Ciphertext(_context);
                ct.Load(_context, ToByteMemoryStream(request.Data));
                var hash = ct.GetHashCode();
                _ciphertextMap[hash] = ct;
                return new CiphertextId {HashCode = hash};
            });

        public override Task<PlaintextId> MakePlaintextInt(PlaintextData request, ServerCallContext context)
        {
            return base.MakePlaintextInt(request, context);
        }

        public override Task<PlaintextId> MakePlaintextLong(PlaintextData request, ServerCallContext context) =>
            Task.Run(() =>
            {
                var p = _encoder.Encode(request.Data);
                var id = p.GetHashCode();
                _plaintextMap[id] = p;
                return new PlaintextId() {HashCode = id};
            });

        ////////

        public override Task<KeyPair> KeyGen(Nothing request, ServerCallContext context)
        {
            return base.KeyGen(request, context);
        }

        public ContextService(ILogger<ContextService> logger) => _logger = logger;
        private static MemoryStream ToByteMemoryStream(ByteString bytes) => new MemoryStream(bytes.ToByteArray());
    }
}