Java.perform(function () {
    console.log("[*] 전자금융 보안 프로그램 초기 동작 검증 시작...");

    // ======================
    // 1. 보안 프로그램 관리 클래스
    // ======================
    const SecurityManager = Java.use("com.example.security.SecurityManager"); // 보안 프로그램 관리 클래스
    const FileSystemManager = Java.use("com.example.filesystem.FileSystemManager"); // 파일 시스템 관련 클래스

    // ===========================================
    // 2. 보안 프로그램 초기화 검증
    // ===========================================
    SecurityManager.initialize.implementation = function () {
        console.log("[*] initialize 호출됨");

        // 보안 프로그램 초기화 동작 확인
        const result = this.initialize();
        console.log(`[+] 보안 프로그램 초기화 결과: ${result ? "성공" : "실패"}`);
        
        // 초기화 실패 시 경고 로그
        if (!result) {
            console.log("[!] 경고: 보안 프로그램 초기화에 실패하였습니다. 설정 문제를 점검하세요.");
        }
        return result;
    };

    // ===========================================
    // 3. 보안 프로그램 실행 여부 확인
    // ===========================================
    SecurityManager.isRunning.implementation = function () {
        console.log("[*] isRunning 호출됨");

        // 보안 프로그램 실행 상태 확인
        const result = this.isRunning();
        console.log(`[+] 보안 프로그램 실행 상태: ${result ? "실행 중" : "미동작"}`);
        return result;
    };

    // ===========================================
    // 4. 중요 파일 및 데이터 보호 확인
    // ===========================================
    FileSystemManager.encryptFile.implementation = function (filePath) {
        console.log(`[+] encryptFile 호출됨 - 파일 경로: ${filePath}`);

        // 파일 암호화 동작 확인
        const result = this.encryptFile(filePath);
        console.log(`[+] 파일 암호화 처리 결과: ${result ? "성공" : "실패"}`);

        if (!result) {
            console.log("[!] 경고: 파일 암호화 실패 → 중요 정보가 유출될 가능성이 있습니다.");
        }
        return result;
    };

    FileSystemManager.decryptFile.implementation = function (filePath) {
        console.log(`[+] decryptFile 호출됨 - 파일 경로: ${filePath}`);

        // 파일 복호화 동작 확인
        const result = this.decryptFile(filePath);
        console.log(`[+] 파일 복호화 처리 결과: ${result ? "성공" : "실패"}`);

        if (!result) {
            console.log("[!] 경고: 파일 복호화 실패 → 파일 접근 문제가 발생할 수 있습니다.");
        }
        return result;
    };

    // ===========================================
    // 5. 초기 상태에서 보안 설정 확인
    // ===========================================
    SecurityManager.getSecuritySettings.implementation = function () {
        console.log("[*] getSecuritySettings 호출됨");

        // 보안 설정 상태 확인
        const settings = this.getSecuritySettings();
        console.log(`[+] 초기 보안 설정: ${JSON.stringify(settings)}`);

        if (!settings || settings.enabled === false) {
            console.log("[!] 경고: 초기 보안 설정이 비활성화되어 있습니다. 보안 프로그램이 제대로 작동하지 않을 수 있습니다.");
        }
        return settings;
    };

    console.log("[*] 전자금융 보안 프로그램 초기 동작 검증 완료.");
});
