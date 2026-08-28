import java.security.MessageDigest;
import java.util.Random;
import java.io.File;

class Vuln {
    String password = "hunter2";

    void sqlInjection(String userInput) throws Exception {
        stmt.executeQuery("SELECT * FROM t WHERE id=" + userInput);
    }

    void commandInjection(String userInput) throws Exception {
        Runtime.getRuntime().exec("ls " + userInput);
    }

    void weakHash() throws Exception {
        MessageDigest.getInstance("MD5");
    }

    void insecureRandom() {
        new Random();
    }

    void zipSlip(File dir, java.util.zip.ZipEntry entry) {
        new File(dir, entry.getName());
    }

    void emptyCatch() {
        try {
            doWork();
        } catch (Exception e) {}
    }
}
