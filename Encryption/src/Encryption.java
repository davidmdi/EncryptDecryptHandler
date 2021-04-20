
import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;


import static java.nio.file.StandardOpenOption.APPEND;

public class Encryption {
    /** At those lines we can change the provider... **/
    private static final String MESSAGE_DIGEST_PROVIDER = "SUN";
    private static final String SIGN_PROVIDER = "SunRsaSign";
    private static final String CIPHER_PROVIDER = "SunJCE";
    private static final String KEY_PROVIDER = "SunJCE";
    private static final String RSA_PROVIDER = "SunJCE";
    /***************************************************/


    public static void main(String[] args)  {
        try {
            byte[] data = getDataFromFile(); // Reads and converts plane-text to byte array
            createDS(data); // Signs and saves the digital signature in conf file
            encryptData(data);// handles the data encryption (saves the encrypted symmetric key in conf file)
        }catch (Exception e){
            System.out.println("Error: " + e.getMessage());
        }

    }

    private static byte[] getDataFromFile() throws Exception {
        System.out.println("importing data from plaintext.txt file...");
        Path path = Paths.get("../plaintext.txt");
        byte[] data = Files.readAllBytes(path);
        System.out.println("Imported successfully");
        return data;
    }

    private static void createDS(byte[] data) throws Exception {
        System.out.println("Creating digital signature...");
        PrivateKey certPrivateKey = getCertPrivateKeyFromJksFile();
        Signature dsa = Signature.getInstance("SHA256withRSA",SIGN_PROVIDER);
        dsa.initSign(certPrivateKey);
        dsa.update(data);
        byte[] signABytes = dsa.sign();
        System.out.println("Saving digital signature in conf file... ");
        File confFile = new File("../conf.txt");
        confFile.createNewFile();
        Path conf = Paths.get("../conf.txt");
        Files.write(conf,signABytes);
        System.out.println("Saved successfully");
        System.out.println("Digital signature created successfully");
    }

    private static PrivateKey getCertPrivateKeyFromJksFile() throws Exception {
        System.out.println("Importing encryptors private key for signing...");
        char[] password = "123456".toCharArray();
        String alias = "encrypt";
        FileInputStream fIn = new FileInputStream("files\\encrypt.jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fIn, password);
        System.out.println("Imported successfully");
        return (PrivateKey) keystore.getKey(alias,password);
    }

    private static void encryptData(byte[] data) throws Exception {
        System.out.println("Encrypting data...");
        FileOutputStream fos = new FileOutputStream("../encrypt.txt");
        SecretKey symKey = createSymmetricKey();
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding",CIPHER_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE,symKey);
        CipherOutputStream cos = new CipherOutputStream(fos,cipher);
        cos.write(data);
        cos.close(); fos.close();
        saveConfiguration(cipher , symKey );
        System.out.println("Encrypted successfully");
    }

    private static void saveConfiguration(Cipher cipher, SecretKey symKey) throws Exception{
        System.out.println("Saving CTR's mode IV and  encrypted symmetric key in conf.txt...");
        byte[] key = symKey.getEncoded();
        byte[] encryptedKey =  encryptSymmetricKey(key);
        System.out.println("Encrypted successfully");
        byte[] parameter = cipher.getParameters().getEncoded();
        AlgorithmParameters x = cipher.getParameters();
        Path conf = Paths.get("../conf.txt");
        Files.write(conf,encryptedKey, APPEND);
        Files.write(conf,parameter, APPEND);
        System.out.println("IV and encrypted Key saved successfully");
    }

    private static byte[] encryptSymmetricKey(byte[] key) throws Exception {
        System.out.println("Encrypting symmetric key with RSA...");
        FileInputStream fIn = new FileInputStream("files\\encrypt.jks");
        KeyStore keystore = KeyStore.getInstance("JKS");
        char[] password = "123456".toCharArray();
        String alias = "decrypt";
        keystore.load(fIn, password);
        Certificate cert = keystore.getCertificate(alias); // receivers certificate
        PublicKey recPublicKey = cert.getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA",RSA_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE,recPublicKey);
        return cipher.doFinal(key); // returns encrypted symmetric key...
    }

    private static SecretKey createSymmetricKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES",KEY_PROVIDER);
        return kg.generateKey();
    }

}


