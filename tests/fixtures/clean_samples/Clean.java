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
        int rawSize = Integer.parseInt(request.getParameter("size"));
        if (rawSize > 0 && rawSize < 1_000_000) {
            int size = rawSize * 1024;
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
}
