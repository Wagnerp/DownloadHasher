/*
Copyright (c) 2013 "Zachary Graber"

This file is part of DownloadHasher.

Veil is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace DownloadHasher
{
    class Hash
    {
        public enum HashAlg
        {
            MD5,
            RIPEMD160,
            SHA1,
            SHA256,
            SHA384,
            SHA512
        };

        public string GetFileHash(HashAlg alg, string filepath)
        {
            // get the hash of a file, with pre implemented algorithms
            switch (alg)
            {
                case (HashAlg.MD5):
                    using (HashAlgorithm hash = MD5.Create()) return HashAlgFile(hash, filepath);
                case (HashAlg.RIPEMD160):
                    using (HashAlgorithm hash = RIPEMD160.Create()) return HashAlgFile(hash, filepath);
                case (HashAlg.SHA1):
                    using (HashAlgorithm hash = SHA1.Create()) return HashAlgFile(hash, filepath);
                case (HashAlg.SHA256):
                    using (HashAlgorithm hash = SHA256.Create()) return HashAlgFile(hash, filepath);
                case (HashAlg.SHA384):
                    using (HashAlgorithm hash = SHA384.Create()) return HashAlgFile(hash, filepath);
                case (HashAlg.SHA512):
                    using (HashAlgorithm hash = SHA512.Create()) return HashAlgFile(hash, filepath);
                default:
                    throw new NotImplementedException("The selected algorithm has not been implemented");
            }
        }

        private string HashAlgFile(HashAlgorithm alg, string filepath)
        {
            // get hash bytes
            byte[] data;
            using (FileStream source = new FileStream(filepath, FileMode.Open)) data = alg.ComputeHash(source);

            // convert hash bytes to a hex string and return
            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++) sBuilder.Append(data[i].ToString("x2"));
            return sBuilder.ToString();
        }

        public string GetFileHash(HashAlg alg, Stream source)
        {
            // get the hash of a file, with pre implemented algorithms
            switch (alg)
            {
                case (HashAlg.MD5):
                    using (HashAlgorithm hash = MD5.Create()) return HashAlgFile(hash, source);
                case (HashAlg.RIPEMD160):
                    using (HashAlgorithm hash = RIPEMD160.Create()) return HashAlgFile(hash, source);
                case (HashAlg.SHA1):
                    using (HashAlgorithm hash = SHA1.Create()) return HashAlgFile(hash, source);
                case (HashAlg.SHA256):
                    using (HashAlgorithm hash = SHA256.Create()) return HashAlgFile(hash, source);
                case (HashAlg.SHA384):
                    using (HashAlgorithm hash = SHA384.Create()) return HashAlgFile(hash, source);
                case (HashAlg.SHA512):
                    using (HashAlgorithm hash = SHA512.Create()) return HashAlgFile(hash, source);
                default:
                    throw new NotImplementedException("The selected algorithm has not been implemented");
            }
        }

        private string HashAlgFile(HashAlgorithm alg, Stream source)
        {
            // get hash bytes
            byte[] data;
            data = alg.ComputeHash(source);

            // convert hash bytes to a hex string and return
            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++) sBuilder.Append(data[i].ToString("x2"));
            return sBuilder.ToString();
        }
    }
}
