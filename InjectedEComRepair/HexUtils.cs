using System;
using System.Collections.Generic;
using System.Text;

namespace InjectedEComRepair
{
    public static class HexUtils
    {
        public static string ToHexString(this byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    sb.Append(bytes[i].ToString("X2"));
                }
            }
            return sb.ToString();
        }
    }
}
