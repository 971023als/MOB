Java.perform(function () {
    console.log("[*] Starting HTTPS Cipher Suite Inspection");

    // SSLParameters 클래스 후킹
    var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

    SSLParametersClass.setCipherSuites.implementation = function (suites) {
        console.log("[*] Hooking SSLParameters.setCipherSuites()");
        console.log("[*] Cipher Suites being set: " + suites.join(", "));

        // 취약한 암호화 알고리즘 탐지
        suites.forEach(function (suite) {
            if (suite.includes("RC4") || suite.includes("RC2") || suite.includes("DES") || suite.includes("3DES") || suite.includes("NULL")) {
                console.warn("[!] Insecure Cipher Suite Detected: " + suite);
            } else {
                console.log("[*] Secure Cipher Suite: " + suite);
            }
        });

        return this.setCipherSuites(suites);
    };

    // SSLSocketFactory 클래스 후킹
    var SSLSocketFactoryClass = Java.use("javax.net.ssl.SSLSocketFactory");

    SSLSocketFactoryClass.getDefaultCipherSuites.implementation = function () {
        console.log("[*] Hooking SSLSocketFactory.getDefaultCipherSuites()");

        var suites = this.getDefaultCipherSuites();
        console.log("[*] Default Cipher Suites: " + suites.join(", "));

        suites.forEach(function (suite) {
            if (suite.includes("RC4") || suite.includes("RC2") || suite.includes("DES") || suite.includes("3DES") || suite.includes("NULL")) {
                console.warn("[!] Insecure Cipher Suite Detected: " + suite);
            } else {
                console.log("[*] Secure Cipher Suite: " + suite);
            }
        });

        return suites;
    };

    console.log("[*] Cipher Suite Inspection Hooks Installed");
});
