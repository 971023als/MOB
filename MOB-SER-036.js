Java.perform(function () {
    console.log("[*] HTTPS 취약 컴포넌트 점검 스크립트 시작");

    // OpenSSL 관련 클래스 및 버전 정보 확인
    try {
        var OpenSSLVersionClass = Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLContextImpl");

        OpenSSLVersionClass.getDefault.implementation = function () {
            var result = this.getDefault();
            console.log("[*] OpenSSL getDefault 후킹 완료");
            console.log("[*] OpenSSL 컨텍스트 세부 정보: " + result);
            return result;
        };

        OpenSSLVersionClass.getInstance.overload('java.lang.String').implementation = function (name) {
            console.log(`[+] OpenSSLContext.getInstance('${name}') 호출됨`);
            if (name.includes("TLS")) {
                console.warn(`[!] 잠재적으로 취약한 OpenSSL 컴포넌트 감지됨: ${name}`);
            }
            return this.getInstance(name);
        };
    } catch (error) {
        console.log("[-] OpenSSLContextImpl 클래스를 찾을 수 없음. OpenSSL 점검 생략.");
    }

    // HTTPS 설정 후킹
    var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

    SSLParametersClass.setProtocols.implementation = function (protocols) {
        console.log("[*] SSLParameters.setProtocols() 후킹됨");
        console.log("[*] 설정된 프로토콜: " + protocols.join(", "));

        protocols.forEach(function (protocol) {
            if (["SSLv3", "TLSv1.0", "TLSv1.1"].includes(protocol)) {
                console.warn(`[!] 취약하거나 안전하지 않은 프로토콜 감지됨: ${protocol}`);
            }
        });

        return this.setProtocols(protocols);
    };

    // 특정 취약점 문자열 검사 함수
    function checkVulnerableComponent(component) {
        const vulnerabilities = [
            { name: "Heartbleed", cve: "CVE-2014-0160", affected: "OpenSSL 1.0.1 - 1.0.1f" },
            { name: "CCS Injection", cve: "CVE-2014-0224", affected: "OpenSSL 1.0.1 - 1.0.1h, 1.0.0~0.9.8za" },
            { name: "FREAK Attack", cve: "CVE-2015-0204", affected: "OpenSSL 1.0.1f~1.0.2" },
            { name: "Ticketbleed", cve: "CVE-2016-9244", affected: "F5 BIG-IP 11.6.0~13.0.0" },
            { name: "Padding Oracle", cve: "CVE-2016-2107", affected: "OpenSSL 1.0.1h~1.0.2" }
        ];

        vulnerabilities.forEach(function (vuln) {
            if (component.includes(vuln.name)) {
                console.warn(`[!] 취약한 컴포넌트 감지됨: ${vuln.name} (${vuln.cve})`);
                console.warn(`[!] 영향받는 버전: ${vuln.affected}`);
            }
        });
    }

    console.log("[*] HTTPS 취약 컴포넌트 점검 후킹 완료");
});
