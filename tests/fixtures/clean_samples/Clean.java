import java.security.MessageDigest;
import java.security.SecureRandom;

class Clean {
    void sqlSafe(String userInput) throws Exception {
        stmt.executeQuery("SELECT * FROM t WHERE id = ?");
    }

    void hashSafe() throws Exception {
        MessageDigest.getInstance("SHA-256");
    }

    void randomSafe() {
        new SecureRandom();
    }

    void catchSafe() {
        try {
            doWork();
        } catch (Exception e) {
            log(e);
        }
    }
}
