using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Server
{
    static void Main(string[] args)
    {
        try
        {
            // Lắng nghe kết nối đến port 1234
            TcpListener listener = new TcpListener(IPAddress.Any, 1234);
            listener.Start();
            Console.WriteLine("Waiting for client connection...");

            // Chấp nhận kết nối từ client
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine("Client connected!");

            // Tạo Private Key và Public Key
            using (ECDiffieHellmanCng serverECDH = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
            {
                serverECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                serverECDH.HashAlgorithm = CngAlgorithm.Sha256;

                // Lấy Public Key của server
                byte[] serverPublicKey = serverECDH.PublicKey.ToByteArray();

                // Gửi kích thước Public Key đến client
                byte[] sizeBytes = BitConverter.GetBytes(serverPublicKey.Length);
                client.GetStream().Write(sizeBytes, 0, sizeBytes.Length);

                // Gửi Public Key đến client
                client.GetStream().Write(serverPublicKey, 0, serverPublicKey.Length);

                // Đọc kích thước Public Key từ client
                byte[] clientPublicKeySizeBytes = new byte[4];
                client.GetStream().Read(clientPublicKeySizeBytes, 0, 4);
                int clientPublicKeySize = BitConverter.ToInt32(clientPublicKeySizeBytes, 0);

                // Đọc Public Key từ client
                byte[] clientPublicKeyBytes = new byte[clientPublicKeySize];
                client.GetStream().Read(clientPublicKeyBytes, 0, clientPublicKeySize);

                // Tính toán khóa chung
                CngKey clientPublicKey = CngKey.Import(clientPublicKeyBytes, CngKeyBlobFormat.EccPublicBlob);
                byte[] sharedSecret = serverECDH.DeriveKeyMaterial(clientPublicKey);

                Console.WriteLine("Shared secret key: " + BitConverter.ToString(sharedSecret).Replace("-", ""));
            }

            client.Close();
            listener.Stop();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }

        Console.ReadLine();
    }

}
