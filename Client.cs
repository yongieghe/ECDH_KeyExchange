using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

class Client
{
    static void Main(string[] args)
    {
        try
        {
            // Kết nối tới địa chỉ IP và cổng của server
            TcpClient client = new TcpClient();
            client.Connect(IPAddress.Parse("127.0.0.1"), 1234);
            Console.WriteLine("Connected to server!");

            // Tạo Private Key và Public Key
            using (ECDiffieHellmanCng clientECDH = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
            {
                clientECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                clientECDH.HashAlgorithm = CngAlgorithm.Sha256;

                // Lấy Public Key của client
                byte[] clientPublicKey = clientECDH.PublicKey.ToByteArray();

                // Gửi kích thước Public Key đến server
                byte[] sizeBytes = BitConverter.GetBytes(clientPublicKey.Length);
                client.GetStream().Write(sizeBytes, 0, sizeBytes.Length);

                // Gửi Public Key đến server
                client.GetStream().Write(clientPublicKey, 0, clientPublicKey.Length);

                // Đọc kích thước Public Key từ server
                byte[] serverPublicKeySizeBytes = new byte[4];
                client.GetStream().Read(serverPublicKeySizeBytes, 0, 4);
                int serverPublicKeySize = BitConverter.ToInt32(serverPublicKeySizeBytes, 0);

                // Đọc Public Key từ server
                byte[] serverPublicKeyBytes = new byte[serverPublicKeySize];
                client.GetStream().Read(serverPublicKeyBytes, 0, serverPublicKeySize);

                // Tính toán khóa chung
                CngKey serverPublicKey = CngKey.Import(serverPublicKeyBytes, CngKeyBlobFormat.EccPublicBlob);
                byte[] sharedSecret = clientECDH.DeriveKeyMaterial(serverPublicKey);

                Console.WriteLine("Shared secret key: " + BitConverter.ToString(sharedSecret).Replace("-", ""));
            }

            client.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }

        Console.ReadLine();
    }
}
