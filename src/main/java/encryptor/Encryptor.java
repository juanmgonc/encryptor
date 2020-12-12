package encryptor;

import secure.RandomSalt;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class Encryptor {
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 512;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static String password = "miContrasenia";

    public static void main(String[] args) {
        System.out.println(hashPassword(password, RandomSalt.generateSalt(8)));
    }

    public static String hashPassword (String pass, String salt) {
        char[] chars = pass.toCharArray();
        byte[] bytes = salt.getBytes();

        PBEKeySpec spec = new PBEKeySpec(chars, bytes, ITERATIONS, KEY_LENGTH);

        Arrays.fill(chars, Character.MIN_VALUE);
        Arrays.fill(bytes, Byte.MIN_VALUE);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] securePass = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(securePass);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
        finally {
            spec.clearPassword();
        }
    }

    public static boolean verifyPassword (String password, String key, String salt) {
        String optEncrypted = hashPassword(password, salt);
        if (!optEncrypted.isEmpty()) return false;
        return optEncrypted.equals(key);
    }
}
