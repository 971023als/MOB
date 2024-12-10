Java.perform(function () {
    console.log("[*] 프로그램 무결성 검증 및 변조 프로그램 실행 점검 시작...");

    // ======================
    // 1. 파일 검증 관련 클래스
    // ======================
    const File = Java.use("java.io.File");
    const MessageDigest = Java.use("java.security.MessageDigest");
    const FileInputStream = Java.use("java.io.FileInputStream");

    // ======================
    // 2. APK 파일 무결성 검증
    // ======================
    function verifyAPKIntegrity(apkPath, expectedHash) {
        try {
            console.log(`[+] APK 무결성 검증 시작 - 파일 경로: ${apkPath}`);
            const file = File.$new(apkPath);
            if (!file.exists()) {
                console.log("[!] APK 파일이 존재하지 않음");
                return false;
            }

            const inputStream = FileInputStream.$new(file);
            const buffer = Java.array('byte', Array(1024).fill(0));
            const digest = MessageDigest.getInstance("SHA-256");
            let bytesRead;

            while ((bytesRead = inputStream.read(buffer)) !== -1) {
                digest.update(buffer, 0, bytesRead);
            }

            inputStream.close();
            const hash = digest.digest();
            const hexHash = hash.map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
            console.log(`[+] APK 해시 값: ${hexHash}`);

            if (hexHash === expectedHash) {
                console.log("[+] APK 파일이 무결성을 유지하고 있습니다.");
                return true;
            } else {
                console.log("[!] APK 파일 변조 감지 - 예상 해시와 일치하지 않음");
                return false;
            }
        } catch (err) {
            console.log(`[!] APK 무결성 검증 중 오류 발생: ${err.message}`);
            return false;
        }
    }

    // ======================
    // 3. 실행파일 및 라이브러리 변조 탐지
    // ======================
    const nativeLibraryPaths = [
        "/data/app/com.example.app/lib/arm/libnative.so",
        "/data/app/com.example.app/lib/arm64/libnative.so"
    ];

    function verifyLibraryIntegrity(libraryPath, expectedHash) {
        try {
            console.log(`[+] 라이브러리 무결성 검증 시작 - 파일 경로: ${libraryPath}`);
            const file = File.$new(libraryPath);
            if (!file.exists()) {
                console.log("[!] 라이브러리 파일이 존재하지 않음");
                return false;
            }

            const inputStream = FileInputStream.$new(file);
            const buffer = Java.array('byte', Array(1024).fill(0));
            const digest = MessageDigest.getInstance("SHA-256");
            let bytesRead;

            while ((bytesRead = inputStream.read(buffer)) !== -1) {
                digest.update(buffer, 0, bytesRead);
            }

            inputStream.close();
            const hash = digest.digest();
            const hexHash = hash.map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
            console.log(`[+] 라이브러리 해시 값: ${hexHash}`);

            if (hexHash === expectedHash) {
                console.log("[+] 라이브러리가 무결성을 유지하고 있습니다.");
                return true;
            } else {
                console.log("[!] 라이브러리 변조 감지 - 예상 해시와 일치하지 않음");
                return false;
            }
        } catch (err) {
            console.log(`[!] 라이브러리 무결성 검증 중 오류 발생: ${err.message}`);
            return false;
        }
    }

    // ======================
    // 4. 테스트 실행
    // ======================
    const expectedAPKHash = "expected_hash_of_original_apk"; // 원본 APK의 SHA-256 해시값
    const expectedLibraryHash = "expected_hash_of_original_library"; // 원본 라이브러리의 SHA-256 해시값

    const apkPath = "/data/app/com.example.app/base.apk"; // APK 경로
    const libraryPath = nativeLibraryPaths[0]; // 라이브러리 경로

    Java.scheduleOnMainThread(function () {
        const apkIntegrity = verifyAPKIntegrity(apkPath, expectedAPKHash);
        const libraryIntegrity = verifyLibraryIntegrity(libraryPath, expectedLibraryHash);

        if (!apkIntegrity || !libraryIntegrity) {
            console.log("[!] 변조된 프로그램 또는 라이브러리가 감지되었습니다. 실행 차단 필요.");
        } else {
            console.log("[+] 모든 파일이 무결성을 유지하고 있습니다.");
        }
    });

    console.log("[*] 프로그램 무결성 검증 및 변조 프로그램 실행 점검 완료.");
});
