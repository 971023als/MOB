Java.perform(function () {
    console.log("[*] Starting Authentication Method Verification Hook Script");

    // 민감한 키워드 목록 정의
    var sensitiveKeywords = ["certificate", "otp", "smsCode", "accountNumber", "authToken"];

    // 인증 관련 클래스 후킹
    var AuthClass = Java.use("com.example.app.AuthManager"); // 앱의 실제 인증 클래스명 사용
    var SmsManager = Java.use("android.telephony.SmsManager");
    var KeyStore = Java.use("java.security.KeyStore");
    var AccountManager = Java.use("android.accounts.AccountManager");

    // 인증서 등록 및 사용 검증
    AuthClass.registerCertificate.implementation = function (certData) {
        console.log("[+] Attempt to Register Certificate: " + certData);
        for (var i = 0; i < sensitiveKeywords.length; i++) {
            if (certData.includes(sensitiveKeywords[i])) {
                console.warn("[!] Sensitive Data Found During Certificate Registration: " + certData);
            }
        }
        return this.registerCertificate(certData);
    };

    AuthClass.verifyCertificate.implementation = function (certId) {
        console.log("[+] Verifying Certificate ID: " + certId);
        return this.verifyCertificate(certId);
    };

    // SMS 인증 코드 검증
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent').implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
        console.log("[+] Intercepted SMS Sending:");
        console.log("    Destination: " + destinationAddress);
        console.log("    Message: " + text);
        for (var i = 0; i < sensitiveKeywords.length; i++) {
            if (text.includes(sensitiveKeywords[i])) {
                console.warn("[!] Sensitive Data Found in SMS: " + text);
            }
        }
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
    };

    // 계좌 인증 검증
    AuthClass.verifyAccount.overload('java.lang.String', 'java.lang.String').implementation = function (accountNumber, authCode) {
        console.log("[+] Verifying Account with Number: " + accountNumber);
        if (accountNumber.includes("0000") || accountNumber.includes("test")) {
            console.warn("[!] Test or Invalid Account Number Detected: " + accountNumber);
        }
        return this.verifyAccount(accountNumber, authCode);
    };

    // OTP 인증 검증
    AuthClass.verifyOtp.overload('java.lang.String').implementation = function (otpCode) {
        console.log("[+] Verifying OTP Code: " + otpCode);
        if (otpCode.length < 6) {
            console.warn("[!] Potential Weak OTP Code Detected: " + otpCode);
        }
        return this.verifyOtp(otpCode);
    };

    // KeyStore (인증서) 접근 후킹
    KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
        console.log("[+] KeyStore Access Attempt: " + type);
        return this.getInstance(type);
    };

    // AccountManager (계정 관리) 후킹
    AccountManager.getAccounts.implementation = function () {
        console.log("[*] Intercepted AccountManager.getAccounts");
        var accounts = this.getAccounts();
        for (var i = 0; i < accounts.length; i++) {
            console.log("    Account: " + accounts[i].name);
        }
        return accounts;
    };

    console.log("[*] Authentication Method Verification Hook Script Installed");
});

민감한 키워드 목록 정의 많이 늘리고 분기문도 추가해서 만들어줘