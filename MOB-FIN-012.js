Java.perform(function () {
    console.log("[*] 전자금융 악성코드 방지 프로세스 검증 및 테스트 시작...");

    // ======================
    // 1. 악성코드 방지 관련 클래스
    // ======================
    const MalwareProtectionManager = Java.use("com.example.security.MalwareProtectionManager"); // 악성코드 방지 클래스
    const ProcessManager = Java.use("android.os.Process"); // 프로세스 관리 클래스

    // ===========================================
    // 2. 악성코드 방지 프로세스 동작 검증
    // ===========================================
    MalwareProtectionManager.startProtection.implementation = function () {
        console.log("[*] startProtection 호출됨");

        // 악성코드 방지 프로세스 시작 여부를 로깅
        const result = this.startProtection();
        console.log(`[+] 악성코드 방지 프로세스 시작 결과: ${result}`);
        return result;
    };

    MalwareProtectionManager.isProtectionRunning.implementation = function () {
        console.log("[*] isProtectionRunning 호출됨");

        // 악성코드 방지 프로세스 상태를 확인
        const result = this.isProtectionRunning();
        console.log(`[+] 악성코드 방지 프로세스 실행 중: ${result}`);
        return result;
    };

    // ===========================================
    // 3. 악성코드 방지 프로세스 강제 종료 테스트
    // ===========================================
    MalwareProtectionManager.terminateProtection.implementation = function () {
        console.log("[*] terminateProtection 호출됨");

        // 원래 동작 수행
        const result = this.terminateProtection();
        console.log("[!] 악성코드 방지 프로세스가 강제로 종료되었습니다.");
        return result;
    };

    // ===========================================
    // 4. 강제 종료 후 재구동 여부 검증
    // ===========================================
    MalwareProtectionManager.restartProtection.implementation = function () {
        console.log("[*] restartProtection 호출됨");

        // 원래 동작 수행
        const result = this.restartProtection();
        console.log(`[+] 악성코드 방지 프로세스 재구동 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 5. 강제 프로세스 종료 후 테스트
    // ===========================================
    ProcessManager.killProcess.implementation = function (pid) {
        console.log(`[!] killProcess 호출됨 - 종료 대상 PID: ${pid}`);

        // 특정 프로세스 강제 종료 감지 및 재구동 로직 수행 여부 확인
        if (pid === MalwareProtectionManager.getProtectionPID()) {
            console.log("[!] 악성코드 방지 프로세스 강제 종료 감지 → 재구동 테스트 실행");
            MalwareProtectionManager.restartProtection();
        }

        // 원래 동작 수행
        this.killProcess(pid);
    };

    console.log("[*] 전자금융 악성코드 방지 프로세스 검증 및 테스트 완료.");
});
