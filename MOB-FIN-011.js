Java.perform(function () {
    console.log("[*] 전자금융 OS 변조 탐지 및 우회 후킹 시작...");

    // ======================
    // 1. 루팅/탈옥 탐지 관련 클래스
    // ======================
    const RootDetection = Java.use("com.example.security.RootDetection"); // 루팅 탐지 클래스
    const JailbreakDetection = Java.use("com.example.security.JailbreakDetection"); // 탈옥 탐지 클래스
    const SystemProperties = Java.use("android.os.SystemProperties"); // 시스템 속성 클래스

    // ===========================================
    // 2. 루팅 탐지 메서드 후킹 및 우회
    // ===========================================
    RootDetection.isDeviceRooted.implementation = function () {
        console.log("[*] isDeviceRooted 호출됨");

        // 테스트: 루팅 탐지 결과를 강제적으로 변경
        const originalResult = this.isDeviceRooted();
        console.log(`[+] 원래 루팅 탐지 결과: ${originalResult}`);
        
        const overrideResult = false; // 루팅 탐지를 우회하도록 설정
        console.log(`[+] 테스트: 루팅 탐지 결과를 ${overrideResult}로 변경`);
        return overrideResult;
    };

    // ===========================================
    // 3. 탈옥 탐지 메서드 후킹 및 우회
    // ===========================================
    JailbreakDetection.isDeviceJailbroken.implementation = function () {
        console.log("[*] isDeviceJailbroken 호출됨");

        // 테스트: 탈옥 탐지 결과를 강제적으로 변경
        const originalResult = this.isDeviceJailbroken();
        console.log(`[+] 원래 탈옥 탐지 결과: ${originalResult}`);
        
        const overrideResult = false; // 탈옥 탐지를 우회하도록 설정
        console.log(`[+] 테스트: 탈옥 탐지 결과를 ${overrideResult}로 변경`);
        return overrideResult;
    };

    // ===========================================
    // 4. 시스템 속성을 이용한 탐지 우회
    // ===========================================
    SystemProperties.get.overload("java.lang.String").implementation = function (key) {
        console.log(`[+] SystemProperties.get 호출됨 - 속성 키: ${key}`);
        
        if (key === "ro.build.tags") {
            console.log("[+] 테스트: ro.build.tags 값을 'release-keys'로 위조");
            return "release-keys"; // 루팅 여부를 확인하는 태그를 위조
        }

        if (key === "ro.debuggable") {
            console.log("[+] 테스트: ro.debuggable 값을 '0'으로 위조");
            return "0"; // 디버깅 가능 여부를 숨김
        }

        return this.get(key); // 원래 동작 수행
    };

    // ===========================================
    // 5. 루팅 관련 파일 탐지 후킹 및 우회
    // ===========================================
    const UnixFileSystem = Java.use("java.io.UnixFileSystem");
    UnixFileSystem.checkAccess.implementation = function (file, access) {
        const filePath = file.getAbsolutePath();
        console.log(`[+] checkAccess 호출됨 - 파일 경로: ${filePath}`);
        
        // 루팅 관련 파일 탐지 시 우회 처리
        const commonPaths = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
            "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon"
        ];

        if (commonPaths.includes(filePath)) {
            console.log(`[!] 루팅 관련 파일 접근 감지 → 우회 처리: ${filePath}`);
            return false; // 파일 접근을 차단하여 우회
        }

        return this.checkAccess(file, access); // 원래 동작 수행
    };

    console.log("[*] 전자금융 OS 변조 탐지 및 우회 후킹 완료.");
});
