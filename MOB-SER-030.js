Java.perform(function () {
    console.log("[*] Starting SSL Certificate Integrity Verification Script");

    // [결정 필요] 이 스크립트는 앱의 인증서 검증을 무력화하는 TrustManager를 주입한다.
    // 트래픽 분석(프록시 인터셉트) 같은 테스트 목적에는 필요하지만,
    // 켜둔 채로 운영 앱에 로드하면 중간자 공격에 무방비가 된다.
    // true로 바꿀 때만 주입하고, 기본값 false에서는 관찰 로그만 남긴다.
    var ENABLE_TRUSTMANAGER_BYPASS = false;

    // CN 검증에 사용할 기대 도메인 (실제 테스트 대상 도메인으로 교체)
    var EXPECTED_DOMAIN = "your-expected-domain.com";

    if (!ENABLE_TRUSTMANAGER_BYPASS) {
        console.log("[*] ENABLE_TRUSTMANAGER_BYPASS = false: TrustManager 주입을 건너뜁니다. (인증서 검증 무력화 없음)");
        return;
    }

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
                        if (!subject.includes("CN=" + EXPECTED_DOMAIN)) {
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
