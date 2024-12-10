Java.perform(function () {
    console.log("[*] 확장된 메모리 내 중요정보 점검 시작...");

    // ======================
    // 1. 민감한 데이터 키워드 정의
    // ======================
    const sensitiveKeywords = [
        "주민등록번호", "비밀번호", "OTP", "보안카드", "카드번호", "password",
        "cardnumber", "otp", "securitycard", "ssn",
        "\\d{16}", // 16자리 숫자 (카드번호 형식)
        "\\d{6}-\\d{7}" // 주민등록번호 형식
    ];

    // ======================
    // 2. 메모리 전체 범위 검사
    // ======================
    function scanMemory() {
        console.log("[*] 메모리 전체 범위 검색 시작...");
        const rangeList = Process.enumerateRanges("rw-");

        rangeList.forEach(function (range) {
            try {
                Memory.scanSync(range.base, range.size, "").forEach(function (match) {
                    let content = Memory.readUtf8String(ptr(match.address));
                    if (content && containsSensitiveData(content)) {
                        console.warn(`[!] 민감한 데이터 발견: ${content}`);
                        logSensitiveData(content, match.address);
                        alertUser(`민감한 데이터 발견: ${content}`);
                    }
                });
            } catch (err) {
                console.error(`[!] 메모리 스캔 중 오류 발생: ${err.message}`);
            }
        });

        console.log("[*] 메모리 전체 범위 검색 완료.");
    }

    // ======================
    // 3. 민감한 데이터 키워드 확인
    // ======================
    function containsSensitiveData(data) {
        for (let keyword of sensitiveKeywords) {
            const regex = new RegExp(keyword);
            if (regex.test(data)) {
                return true;
            }
        }
        return false;
    }

    // ======================
    // 4. 민감 데이터 로그 저장
    // ======================
    function logSensitiveData(data, address) {
        const filePath = "/sdcard/sensitive_data_log.txt";
        const fs = Java.use("java.io.FileWriter");
        const fw = fs.$new(filePath, true); // Append mode
        fw.write(`[${new Date().toISOString()}] 발견된 민감 데이터: ${data} (주소: ${address})\n`);
        fw.close();
        console.log(`[+] 민감 데이터 로그 저장 완료: ${filePath}`);
    }

    // ======================
    // 5. 실시간 UI 알림
    // ======================
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

    // ======================
    // 6. 특정 메서드에서 메모리 추적
    // ======================
    const TargetClass = Java.use("com.example.app.TargetClass");
    TargetClass.targetMethod.implementation = function (arg1) {
        console.log("[+] targetMethod 호출 감지");

        let buffer = Memory.alloc(1024); // 1KB 할당
        Memory.copy(buffer, ptr(arg1), 1024); // 메모리 복사

        let content = Memory.readUtf8String(buffer);
        if (containsSensitiveData(content)) {
            console.warn("[!] 민감한 데이터가 메모리에서 감지되었습니다.");
            logSensitiveData(content, arg1);
            alertUser(`메모리에서 민감 데이터 감지: ${content}`);
        }

        return this.targetMethod(arg1);
    };

    // ======================
    // 7. 주기적 메모리 스캔
    // ======================
    setInterval(scanMemory, 30000); // 30초마다 메모리 스캔

    console.log("[*] 확장된 메모리 내 중요정보 점검 완료.");
});
