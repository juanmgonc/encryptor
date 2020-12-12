package secure;

import java.security.SecureRandom;
import java.util.Base64;

public class RandomSalt {

    private static final SecureRandom RAND = new SecureRandom();

    public static String generateSalt (final int length) {

        if (length < 1) {
            System.err.println("Error when trying to generate Salt: length must be > 0");
            return null;
        }

        byte[] salt = new byte[length];
        RAND.nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }
}
