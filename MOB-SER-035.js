Java.perform(function () {
    console.log("[*] HTTPS 암호화 방식 검사 스크립트 시작");

    // SSLParameters 클래스 후킹
    var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

    SSLParametersClass.setCipherSuites.implementation = function (suites) {
        console.log("[*] SSLParameters.setCipherSuites() 후킹됨");
        console.log("[*] 설정 중인 암호화 방식: " + suites.join(", "));

        // 취약한 암호화 방식 검사
        suites.forEach(function (suite) {
            if (isInsecureCipherSuite(suite)) {
                console.warn(`[!] 취약한 암호화 방식 감지됨: ${suite}`);
            } else {
                console.log(`[+] 안전한 암호화 방식: ${suite}`);
            }
        });

        return this.setCipherSuites(suites);
    };

    // SSLSocketFactory 클래스 후킹
    var SSLSocketFactoryClass = Java.use("javax.net.ssl.SSLSocketFactory");

    SSLSocketFactoryClass.getDefaultCipherSuites.implementation = function () {
        console.log("[*] SSLSocketFactory.getDefaultCipherSuites() 후킹됨");

        var suites = this.getDefaultCipherSuites();
        console.log("[*] 기본 암호화 방식: " + suites.join(", "));

        suites.forEach(function (suite) {
            if (isInsecureCipherSuite(suite)) {
                console.warn(`[!] 취약한 암호화 방식 감지됨: ${suite}`);
            } else {
                console.log(`[+] 안전한 암호화 방식: ${suite}`);
            }
        });

        return suites;
    };

    // 취약한 암호화 방식 판별 함수
    function isInsecureCipherSuite(suite) {
        const insecurePatterns = ["RC4", "RC2", "DES", "3DES", "NULL"];
        return insecurePatterns.some(pattern => suite.includes(pattern));
    }

    console.log("[*] HTTPS 암호화 방식 검사 후킹 완료");
});
