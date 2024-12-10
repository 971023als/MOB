Java.perform(function () {
    console.log("[*] 인증 메서드 검증 후킹 스크립트 시작");

    // 민감한 키워드 목록 정의 (확장)
    var sensitiveKeywords = [
        "certificate", "otp", "smsCode", "accountNumber", "authToken",
        "password", "key", "privateKey", "accessToken", "refreshToken",
        "securityCode", "pin", "userId", "secret", "apiKey"
    ];

    // 인증 관련 클래스 후킹
    var AuthClass = Java.use("com.example.app.AuthManager"); // 앱의 실제 인증 클래스명 사용
    var SmsManager = Java.use("android.telephony.SmsManager");
    var KeyStore = Java.use("java.security.KeyStore");
    var AccountManager = Java.use("android.accounts.AccountManager");

    // 인증서 등록 및 사용 검증
    AuthClass.registerCertificate.implementation = function (certData) {
        console.log("[+] 인증서 등록 시도 감지: " + certData);
        for (var i = 0; i < sensitiveKeywords.length; i++) {
            if (certData.includes(sensitiveKeywords[i])) {
                console.warn("[!] 민감한 데이터 감지됨 (인증서 등록 중): " + certData);
            }
        }
        if (certData.length < 10) {
            console.warn("[!] 비정상적으로 짧은 인증서 데이터 감지");
        }
        return this.registerCertificate(certData);
    };

    AuthClass.verifyCertificate.implementation = function (certId) {
        console.log("[+] 인증서 검증 시도: ID = " + certId);
        if (certId.includes("test") || certId.includes("dummy")) {
            console.warn("[!] 테스트 또는 더미 인증서 ID 감지됨: " + certId);
        }
        return this.verifyCertificate(certId);
    };

    // SMS 인증 코드 검증
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent').implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
        console.log("[+] SMS 전송 시도 감지:");
        console.log("    수신자 주소: " + destinationAddress);
        console.log("    메시지 내용: " + text);
        for (var i = 0; i < sensitiveKeywords.length; i++) {
            if (text.includes(sensitiveKeywords[i])) {
                console.warn("[!] SMS 내 민감한 데이터 감지됨: " + text);
            }
        }
        if (destinationAddress.startsWith("+999") || text.includes("test")) {
            console.warn("[!] 테스트용 SMS 전송 감지");
        }
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
    };

    // 계좌 인증 검증
    AuthClass.verifyAccount.overload('java.lang.String', 'java.lang.String').implementation = function (accountNumber, authCode) {
        console.log("[+] 계좌 검증 시도: 계좌번호 = " + accountNumber + ", 인증코드 = " + authCode);
        if (accountNumber.includes("0000") || accountNumber.includes("test") || accountNumber.length < 8) {
            console.warn("[!] 비정상 계좌번호 감지됨: " + accountNumber);
        }
        if (authCode.length < 4) {
            console.warn("[!] 약한 인증코드 감지됨: " + authCode);
        }
        return this.verifyAccount(accountNumber, authCode);
    };

    // OTP 인증 검증
    AuthClass.verifyOtp.overload('java.lang.String').implementation = function (otpCode) {
        console.log("[+] OTP 코드 검증 시도: " + otpCode);
        if (otpCode.length < 6 || otpCode.match(/^[0-9]{6}$/) === null) {
            console.warn("[!] 약한 또는 비정상 OTP 코드 감지됨: " + otpCode);
        }
        return this.verifyOtp(otpCode);
    };

    // KeyStore (인증서) 접근 후킹
    KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
        console.log("[+] KeyStore 접근 시도 감지: " + type);
        if (type === "PKCS12" || type === "JKS") {
            console.log("[+] 보안 인증서 형식 사용: " + type);
        } else {
            console.warn("[!] 비정상 인증서 형식 감지: " + type);
        }
        return this.getInstance(type);
    };

    // AccountManager (계정 관리) 후킹
    AccountManager.getAccounts.implementation = function () {
        console.log("[*] AccountManager.getAccounts 호출됨");
        var accounts = this.getAccounts();
        for (var i = 0; i < accounts.length; i++) {
            console.log("    계정 이름: " + accounts[i].name);
            if (accounts[i].name.includes("test") || accounts[i].name.includes("dummy")) {
                console.warn("[!] 테스트 계정 감지됨: " + accounts[i].name);
            }
        }
        return accounts;
    };

    console.log("[*] 인증 메서드 검증 후킹 스크립트 설치 완료");
});
