using System.Runtime.CompilerServices;

public static class ConstantTimeComparer
{
    /// <summary>
    /// Determine the equality of two byte sequences in an amount of time which depends on
    /// the length of the sequences, but not the values.
    /// </summary>
    /// <param name="left">The first buffer to compare.</param>
    /// <param name="right">The second buffer to compare.</param>
    /// <returns>
    ///   <c>true</c> if <paramref name="left"/> and <paramref name="right"/> have the same
    ///   values for <see cref="ReadOnlySpan{T}.Length"/> and the same contents, <c>false</c>
    ///   otherwise.
    /// </returns>
    /// <remarks>
    ///   This method compares two buffers' contents for equality in a manner which does not
    ///   leak timing information, making it ideal for use within cryptographic routines.
    ///   This method will short-circuit and return <c>false</c> only if <paramref name="left"/>
    ///   and <paramref name="right"/> have different lengths.
    ///
    ///   Fixed-time behavior is guaranteed in all other cases, including if <paramref name="left"/>
    ///   and <paramref name="right"/> reference the same address.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        // NoOptimization because we want this method to be exactly as non-short-circuiting
        // as written.
        //
        // NoInlining because the NoOptimization would get lost if the method got inlined.

        if (left.Length != right.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> leftSpan = new ReadOnlySpan<byte>(left);
        ReadOnlySpan<byte> rightSpan = new ReadOnlySpan<byte>(right);

        int length = leftSpan.Length;
        int accum = 0;

        for (int i = 0; i < length; i++)
        {
            accum |= leftSpan[i] ^ rightSpan[i];//Accumulates differences in a bitwise xor manner. preferred method

            //accum |= leftSpan[i] - rightSpan[i];// Accumulates differences using arithmetic subtraction. slight concerns about signed integer overflow & the behavior of subtraction in certain edge cases.
        }

        return accum == 0;
    }
}