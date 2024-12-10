Java.perform(function () {
    console.log("[*] Starting SSL Certificate Integrity Verification Script");

    // SSLContext 클래스 후킹
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // 기본 TrustManager 대체
    SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    ).implementation = function (keyManagers, trustManagers, secureRandom) {
        console.log("[*] Custom TrustManager Injection");

        var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var customTrustManager = Java.registerClass({
            name: "com.example.CustomTrustManager",
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {
                    console.log("[*] Client certificate trusted");
                },
                checkServerTrusted: function (chain, authType) {
                    console.log("[*] Server certificate validation:");
                    for (var i = 0; i < chain.length; i++) {
                        var cert = chain[i];
                        console.log("    Subject: " + cert.getSubjectDN().getName());
                        console.log("    Issuer: " + cert.getIssuerDN().getName());
                        console.log("    Serial Number: " + cert.getSerialNumber().toString(16));

                        // CN 값 검증
                        var subject = cert.getSubjectDN().getName();
                        if (!subject.includes("CN=your-expected-domain.com")) {
                            console.warn("[!] CN mismatch detected!");
                        }

                        // 유효기간 검증
                        var currentDate = new Date();
                        if (cert.getNotAfter().getTime() < currentDate.getTime()) {
                            console.warn("[!] Certificate expired!");
                        }

                        // 자체 서명 검증
                        if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
                            console.warn("[!] Self-signed certificate detected!");
                        }
                    }
                },
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });

        // TrustManager 배열에 추가
        var customTrustManagers = [customTrustManager.$new()];
        this.init(keyManagers, customTrustManagers, secureRandom);
    };

    console.log("[*] SSL TrustManager Hook installed successfully");
});
