RSA usage

```C#
RSA rsa = new RSA(512);
rsa.GenerateKeys();

string encrypted = rsa.Encrypt("hello world");
Console.WriteLine("encrypted: " + encrypted);

string decrypted = rsa.Decrypt(encrypted);
Console.WriteLine("decrypted: " + decrypted);
Console.WriteLine("stop");
Console.ReadKey();
```
![image](https://github.com/user-attachments/assets/e0e73b4a-fcee-411b-acf8-1377b578faf2)
