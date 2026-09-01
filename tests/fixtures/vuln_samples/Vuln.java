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
}
