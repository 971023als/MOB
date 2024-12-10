Java.perform(function () {
    console.log("[*] Starting HTTPS Vulnerable Component Inspection");

    // OpenSSL 관련 클래스 및 버전 정보 확인
    try {
        var OpenSSLVersionClass = Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLContextImpl");
        
        OpenSSLVersionClass.getDefault.implementation = function () {
            var result = this.getDefault();
            console.log("[*] Hooked OpenSSL getDefault");
            console.log("[*] OpenSSL Context Details: " + result);
            return result;
        };
        
        OpenSSLVersionClass.getInstance.overload('java.lang.String').implementation = function (name) {
            console.log("[*] Hooking OpenSSLContext.getInstance('" + name + "')");
            if (name.includes("TLS")) {
                console.warn("[!] Potentially Vulnerable OpenSSL Component Detected: " + name);
            }
            return this.getInstance(name);
        };
    } catch (error) {
        console.log("[-] OpenSSLContextImpl Class Not Found. Skipping OpenSSL Inspection.");
    }

    // HTTPS 설정 후킹
    var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

    SSLParametersClass.setProtocols.implementation = function (protocols) {
        console.log("[*] Hooked SSLParameters.setProtocols()");
        console.log("[*] Configured Protocols: " + protocols.join(", "));

        protocols.forEach(function (protocol) {
            if (protocol === "SSLv3" || protocol === "TLSv1.0" || protocol === "TLSv1.1") {
                console.warn("[!] Insecure Protocol Detected: " + protocol);
            }
        });

        return this.setProtocols(protocols);
    };

    // 특정 취약점 문자열 검사
    function checkVulnerableComponent(component) {
        var vulnerabilities = [
            { name: "Heartbleed", cve: "CVE-2014-0160", description: "OpenSSL 1.0.1 - 1.0.1f" },
            { name: "CCS Injection", cve: "CVE-2014-0224", description: "OpenSSL 1.0.1 - 1.0.1h, 1.0.0~0.9.8za" },
            { name: "FREAK Attack", cve: "CVE-2015-0204", description: "OpenSSL 1.0.1f~1.0.2" },
            { name: "Ticketbleed", cve: "CVE-2016-9244", description: "F5 BIG-IP 11.6.0~13.0.0" },
            { name: "Padding Oracle", cve: "CVE-2016-2107", description: "OpenSSL 1.0.1h~1.0.2" }
        ];

        vulnerabilities.forEach(function (vuln) {
            if (component.includes(vuln.name)) {
                console.warn(`[!] Detected Vulnerable Component: ${vuln.name} (${vuln.cve}) - ${vuln.description}`);
            }
        });
    }

    console.log("[*] HTTPS Vulnerable Component Inspection Hooks Installed");
});
