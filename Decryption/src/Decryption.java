import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;



public class Decryption {
    /**
     * At those lines we can change the provider...
     **/
    private static final String MESSAGE_DIGEST_PROVIDER = "SUN";
    private static final String PARAMETERS_PROVIDER = "SunJCE";
    private static final String SIGN_PROVIDER = "SunRsaSign";
    private static final String CIPHER_PROVIDER = "SunJCE";
    private static final String KEY_PROVIDER = "SunJCE";
    private static final String RSA_PROVIDER = "SunJCE";


    public static void main(String[] args) throws Exception {
       try {
           byte[] signature = new byte[256];
           byte[] encKey = new byte[256];
           byte[] algParameters = new byte[18];
           decodeConfFile(signature, encKey, algParameters);
           run( signature, encKey, algParameters); // start processing data...
       }catch (Exception e){
           System.out.println("Error: " + e.getMessage());
       }
    }

    private static void decodeConfFile(byte[] signature, byte[] encKey, byte[] algParameters) throws
            IOException {
        System.out.println("Decoding conf.txt file...");
        Path path = Paths.get("../conf.txt");// gets
        byte[] data = Files.readAllBytes(path);
        for (int i = 0; i < 256; i++) {
            signature[i] = data[i];
        }
        int j = 256; // encrypted symmetric key starts from here
        for (int i = 0; i < 256; i++) {
            encKey[i] = data[j++];
        }
        j = 256 + 256; // algorithm parameters starts from here...
        for (int i = 0; i < 18; i++) {
            algParameters[i] = data[j++];
        }
        System.out.println("conf.txt Decoded successfully");
    }

    private static void run(byte[] signature, byte[] encKey, byte[] algParameters)
            throws Exception {
        byte[] symKeyAsBytes = decrypteSymKey(encKey);
        System.out.println("Decrypted symmetric key successfully");
        SecretKey symKey = new SecretKeySpec(symKeyAsBytes,"AES");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES", PARAMETERS_PROVIDER);
        parameters.init(algParameters);
        byte[] decryptData = processData(symKey,parameters);
        if(checkDS(decryptData,signature)){
            System.out.println("Digital signature confirmed ");
            writeToFile(decryptData);
        }

        else{
            System.out.println("Error: Signature mismatch.");
            System.out.println("Not Creating decrypt file...");
        }
    }

    private static void writeToFile(byte[] decryptData)throws Exception {
        System.out.println("Writing decrypted data to decrypted.txt file...");
        FileOutputStream fos = new FileOutputStream("..\\decrypted.txt");
        fos.write(decryptData);
        System.out.println("Wrote successfully");
        fos.close();
    }

    private static boolean checkDS(byte[] decryptData, byte[] signature) throws Exception{
        System.out.println("Starting check digital signature..");
        System.out.println("Importing encryptors certificate's public key... ");
        PublicKey publicKey = getPublicKeyFromCert();
        System.out.println("Imported encryptors certificate's public key successfully ");
        Signature dsa = Signature.getInstance("SHA256withRSA",SIGN_PROVIDER);
        dsa.initVerify(publicKey);
        dsa.update(decryptData);
        return dsa.verify(signature);
    }

    private static PublicKey getPublicKeyFromCert() throws Exception {
        FileInputStream fIn = new FileInputStream("files\\decrypt.jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        char[] password = "654321".toCharArray();
        String alias = "encrypt";
        keystore.load(fIn, password);
        Certificate cert = keystore.getCertificate(alias); // receivers certificate
        return  cert.getPublicKey();
    }

    private static byte[] processData(SecretKey symKey, AlgorithmParameters parameters)throws Exception {
        System.out.println("Decrypting data...");
        FileInputStream fis = new FileInputStream("..\\encrypt.txt");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding",CIPHER_PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE,symKey,parameters);
        CipherInputStream cis = new CipherInputStream(fis,cipher);
        byte[] buffer = cis.readAllBytes();
        System.out.println("Data decrypted successfully");
        fis.close(); cis.close();
        return buffer;
    }

    private static byte[] decrypteSymKey(byte[] encKey) throws Exception{
        System.out.println("Decrypting symmetric key...");
        FileInputStream decFile = new FileInputStream("files\\decrypt.jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        char[] password = "654321".toCharArray();
        String alias = "decrypt";
        keystore.load(decFile, password);
        PrivateKey pkey = (PrivateKey) keystore.getKey(alias, password);
        Cipher decCipher = Cipher.getInstance("RSA",RSA_PROVIDER);
        decCipher.init(Cipher.DECRYPT_MODE,pkey);
        byte[] symKey =  decCipher.doFinal(encKey);
        return symKey;
    }

}

