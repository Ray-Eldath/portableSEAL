using System.IO;
using Google.Protobuf;
using Microsoft.Research.SEAL;
using portableSEAL.Services;

namespace Server.Utils
{
    internal static class Serializer
    {
        internal const ComprModeType CompressionMode = ComprModeType.Deflate;

        internal static SerializedCiphertext SerializeCiphertext(Ciphertext ct)
        {
            // 无可奈何的三部曲
            var r = new MemoryStream((int) ct.SaveSize(CompressionMode));
            ct.Save(r, CompressionMode);
            r.Position = 0;
            // 无可奈何的三部曲 —— 终结
            return new SerializedCiphertext {Data = ToByteString(r)};
        }

        internal static Ciphertext DeserializeCiphertext(SEALContext context, ByteString bytes)
        {
            var ct = new Ciphertext(context);
            ct.Load(context, ToByteMemoryStream(bytes));
            return ct;
        }

        internal static ByteString ToByteString(Stream stream) => ByteString.FromStream(stream);
        internal static Stream ToByteMemoryStream(ByteString bytes) => new MemoryStream(bytes.ToByteArray());
    }
}