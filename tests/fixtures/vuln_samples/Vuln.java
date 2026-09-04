import java.security.MessageDigest;
import java.util.Random;
import java.io.File;
import java.io.FileInputStream;
import java.net.URL;

class Vuln {
    String password = "hunter2";
    static final int MAX_RETRY = 5;
    static final int TIMEOUT_SEC = 5;

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

    void dangerousFileUpload(File dir, org.springframework.web.multipart.MultipartFile file) {
        new File(dir, file.getOriginalFilename());
    }

    void xpathInjection(javax.xml.xpath.XPath xpath, String name, org.w3c.dom.Document doc) throws Exception {
        xpath.evaluate("//user[@name='" + name + "']", doc);
    }

    void httpResponseSplitting(javax.servlet.http.HttpServletResponse response, javax.servlet.http.HttpServletRequest request) {
        response.setHeader("Location", request.getParameter("next"));
    }

    void integerOverflow(javax.servlet.http.HttpServletRequest request) {
        int size = Integer.parseInt(request.getParameter("size")) * 1024;
    }

    void improperAuthorization(User user, javax.servlet.http.HttpServletRequest request) {
        user.setRole(request.getParameter("role"));
    }

    void unencryptedSensitiveData(User user, javax.servlet.http.HttpServletRequest request) {
        user.setSsn(request.getParameter("ssn"));
    }

    void sensitiveCookie(String value) {
        Cookie cookie = new Cookie("password", value);
    }

    // password=hunter2
    void sensitiveInfoInComment() {}

    private int[] secretData;

    void infiniteLoop() {
        while (true) {
            doWork();
        }
    }

    void errorInfoExposure() {
        try {
            doWork();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void improperExceptionHandling() {
        try {
            doWork();
        } catch (Exception e) {
            log(e);
        }
    }

    void nullDereference(java.util.Map<String, String> map, String key) {
        map.get(key).length();
    }

    void improperResourceRelease(String path) throws Exception {
        FileInputStream stream = new FileInputStream(path);
        stream.read();
    }

    int integerConversionError() {
        return (int) System.currentTimeMillis();
    }

    void uncheckedReturnValue(File file) {
        file.delete();
    }

    void systemDataExposure(javax.servlet.http.HttpServletResponse response) {
        response.setHeader("Server", "Tomcat/9.0");
    }

    public int[] getSecretData() {
        return secretData;
    }

    public Vuln(int[] secretData) {
        this.secretData = secretData;
    }

    void dnsBasedSecurityDecision(java.net.InetAddress addr) {
        String host = addr.getHostName();
    }

    byte[] vulnerableApiUsage(String s) {
        return s.getBytes();
    }

    void osCommandApiMisuse() throws Exception {
        Runtime.getRuntime().exec("ls -la");
    }

    String secretKey = "abc123456789key";

    void xss(javax.servlet.http.HttpServletResponse response, javax.servlet.http.HttpServletRequest request) throws Exception {
        response.getWriter().println(request.getParameter("name"));
    }

    void ssrf(javax.servlet.http.HttpServletRequest request) throws Exception {
        new URL(request.getParameter("url")).openStream();
    }

    void openRedirect(javax.servlet.http.HttpServletResponse response, javax.servlet.http.HttpServletRequest request) throws Exception {
        response.sendRedirect(request.getParameter("next"));
    }

    void hashWithoutSalt(String password) throws Exception {
        MessageDigest.getInstance("SHA-256").digest(password.getBytes());
    }
}
