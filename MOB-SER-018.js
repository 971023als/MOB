Java.perform(function () {
    console.log("[*] SSI Injection 탐지 및 방지 스크립트 실행 중...");

    // SSI 관련 클래스 및 메서드 후킹 (가상 예시)
    const Runtime = Java.use("java.lang.Runtime");
    const ProcessBuilder = Java.use("java.lang.ProcessBuilder");

    // Runtime.exec() 메서드 후킹
    Runtime.exec.overload("java.lang.String").implementation = function (command) {
        console.log("[+] Runtime.exec() 호출 감지");
        console.log("[-] 명령어: " + command);

        if (isSuspiciousCommand(command)) {
            console.warn(`[!] 의심스러운 SSI 명령어 탐지 및 차단: ${command}`);
            alertUser(`SSI Injection 의심 요청 차단: ${command}`);
            throw new Error("SSI Injection 의심 요청 차단");
        }

        return this.exec(command); // 원래 메서드 호출
    };

    // ProcessBuilder.start() 메서드 후킹
    ProcessBuilder.start.implementation = function () {
        console.log("[+] ProcessBuilder.start() 호출 감지");

        const commands = this.command().toString();
        console.log("[-] 명령어: " + commands);

        if (isSuspiciousCommand(commands)) {
            console.warn(`[!] 의심스러운 SSI 명령어 탐지 및 차단: ${commands}`);
            alertUser(`SSI Injection 의심 요청 차단: ${commands}`);
            throw new Error("SSI Injection 의심 요청 차단");
        }

        return this.start(); // 원래 메서드 호출
    };

    // ====================================================
    // 1. Injection 탐지 함수
    // ====================================================
    function isSuspiciousCommand(command) {
        const suspiciousPatterns = ["<!--#exec", "ls", "dir", "echo", "DOCUMENT_NAME"];
        for (let i = 0; i < suspiciousPatterns.length; i++) {
            if (command.includes(suspiciousPatterns[i])) {
                return true;
            }
        }
        return false;
    }

    // ====================================================
    // 2. 사용자 경고 함수
    // ====================================================
    function alertUser(message) {
        Java.scheduleOnMainThread(function () {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const AlertDialog = Java.use("android.app.AlertDialog");
            const Builder = AlertDialog.Builder;

            const builder = Builder.$new(context);
            builder.setTitle("보안 경고");
            builder.setMessage(message);
            builder.setPositiveButton("확인", null);
            builder.show();
        });
    }

    console.log("[*] SSI Injection 탐지 및 방지 준비 완료.");
});
