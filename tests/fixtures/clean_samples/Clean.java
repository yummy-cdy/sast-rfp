import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.FileInputStream;

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
        } catch (java.io.IOException e) {
            log(e);
        }
    }

    void uploadSafe(File dir) {
        new File(dir, java.util.UUID.randomUUID().toString());
    }

    void xpathSafe(javax.xml.xpath.XPath xpath, org.w3c.dom.Document doc) throws Exception {
        xpath.evaluate("//user[@role='admin']", doc);
    }

    void httpHeaderSafe(javax.servlet.http.HttpServletResponse response) {
        response.setHeader("X-Frame-Options", "DENY");
    }

    void integerOverflowSafe(javax.servlet.http.HttpServletRequest request) {
        try {
            int rawSize = Integer.parseInt(request.getParameter("size"));
            if (rawSize > 0 && rawSize < 1_000_000) {
                int size = rawSize * 1024;
            }
        } catch (NumberFormatException e) {
            log(e);
        }
    }

    void authorizationSafe(User user) {
        user.setRole("user");
    }

    void sensitiveDataSafe(User user, String encryptedSsn) {
        user.setSsn(encryptedSsn);
    }

    void cookieSafe(String sessionId) {
        Cookie cookie = new Cookie("session_id", sessionId);
    }

    // this method validates the password
    void commentSafe() {}

    private int[] secretData;

    void loopSafe() {
        while (true) {
            if (shouldStop()) {
                break;
            }
            doWork();
        }
    }

    void errorInfoSafe() {
        try {
            doWork();
        } catch (java.io.IOException e) {
            logger.error(e);
        }
    }

    void nullDereferenceSafe(java.util.Map<String, String> map, String key) {
        String v = map.get(key);
        if (v != null) {
            v.length();
        }
    }

    void resourceReleaseSafe(String path) throws Exception {
        try (FileInputStream stream = new FileInputStream(path)) {
            stream.read();
        }
    }

    long integerConversionSafe() {
        return System.currentTimeMillis();
    }

    void checkedReturnValueSafe(File file) {
        boolean deleted = file.delete();
        if (!deleted) {
            log("delete failed");
        }
    }

    public int[] getSecretDataSafe() {
        return secretData.clone();
    }

    public Clean(int[] secretData) {
        this.secretData = secretData.clone();
    }

    void dnsBasedDecisionSafe(java.net.InetAddress addr) {
        String ip = addr.getHostAddress();
    }

    byte[] apiUsageSafe(String s) throws Exception {
        return s.getBytes("UTF-8");
    }

    void commandApiSafe() throws Exception {
        Runtime.getRuntime().exec(new String[]{"ls", "-la"});
    }
}
