import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.FileInputStream;
import java.net.URL;
import javax.script.ScriptEngine;

class Clean {
    static final int MAX_RETRY = 5;
    static final int TIMEOUT_SEC = 10;

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

    String secretKey = System.getenv("SECRET_KEY");

    void xssSafe(javax.servlet.http.HttpServletResponse response) throws Exception {
        response.getWriter().println("static text");
    }

    void ssrfSafe() throws Exception {
        new URL("https://example.com/fixed").openStream();
    }

    void openRedirectSafe(javax.servlet.http.HttpServletResponse response) throws Exception {
        response.sendRedirect("/home");
    }

    void hashWithSaltSafe(String password, String salt) throws Exception {
        MessageDigest.getInstance("SHA-256").digest((password + salt).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    String codeInjectionSafe(ScriptEngine engine, String fixedScript) throws Exception {
        return (String) engine.eval(fixedScript);
    }
}
