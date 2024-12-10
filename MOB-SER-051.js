Java.perform(function () {
    console.log("[*] Starting Communication Encryption Check Script");

    // HttpURLConnection 후킹
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.setRequestMethod.implementation = function (method) {
        console.log("[+] HttpURLConnection.setRequestMethod() called");
        console.log("    Method: " + method);
        if (method.toUpperCase() === "HTTP") {
            console.warn("[!] Insecure Protocol Detected: HTTP (Unencrypted)");
        }
        return this.setRequestMethod(method);
    };

    // SSL/TLS Context 후킹
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.implementation = function (keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() called");
        var protocol = this.getProtocol();
        console.log("    Protocol: " + protocol);
        if (protocol === "SSL" || protocol === "TLSv1" || protocol === "TLSv1.1") {
            console.warn("[!] Weak or Deprecated Protocol Detected: " + protocol);
        }
        return this.init(keyManager, trustManager, secureRandom);
    };

    // OkHttp 클라이언트의 HTTP/HTTPS 호출 후킹
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    Request$Builder = Java.use("okhttp3.Request$Builder");

    Request$Builder.build.implementation = function () {
        var request = this.build();
        var url = request.url().toString();
        console.log("[+] HTTP Request Intercepted: " + url);
        if (url.startsWith("http://")) {
            console.warn("[!] Insecure HTTP URL Detected: " + url);
        } else if (url.startsWith("https://")) {
            console.log("[+] Secure HTTPS URL: " + url);
        }
        return request;
    };

    console.log("[*] Communication Encryption Check Script Installed");
});
