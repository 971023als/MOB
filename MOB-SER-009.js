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

        // 기존 코드는 빈 패턴("")으로 스캔해 범위 전체가 매치되고,
        // 각 주소를 무작정 UTF-8 문자열로 읽어 사실상 모든 메모리를 "민감 데이터"로 오탐했다.
        // 리터럴 키워드별로 스캔한다. (정규식 형태 키워드는 스캔 패턴으로 못 쓰므로 제외)
        const literalKeywords = sensitiveKeywords.filter(k => k.indexOf("\\") === -1);

        rangeList.forEach(function (range) {
            literalKeywords.forEach(function (keyword) {
                try {
                    const pattern = toHexPattern(keyword);
                    Memory.scanSync(range.base, range.size, pattern).forEach(function (match) {
                        let content = null;
                        try {
                            content = Memory.readUtf8String(ptr(match.address), 128);
                        } catch (e) { /* 문자열이 아니면 건너뜀 */ }
                        if (content) {
                            console.warn(`[!] 민감 키워드 "${keyword}" 발견 (주소: ${match.address})`);
                            logSensitiveData(keyword, match.address);
                            alertUser(`메모리에서 민감 키워드 감지: ${keyword}`);
                        }
                    });
                } catch (err) {
                    console.error(`[!] 메모리 스캔 중 오류 발생: ${err.message}`);
                }
            });
        });

        console.log("[*] 메모리 전체 범위 검색 완료.");
    }

    // 문자열을 Memory.scanSync용 hex 패턴("70 61 73 73")으로 변환
    function toHexPattern(str) {
        const bytes = [];
        for (let i = 0; i < str.length; i++) {
            bytes.push(str.charCodeAt(i).toString(16).padStart(2, "0"));
        }
        return bytes.join(" ");
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
        // 기존 코드는 /sdcard(공용 저장소, 다른 앱도 읽기 가능)에 민감 데이터를 기록했다.
        // 앱 내부 디렉터리에만 기록하고, 내용 전문이 아니라 키워드와 주소만 남긴다.
        try {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const filePath = context.getFilesDir().getAbsolutePath() + "/sensitive_data_log.txt";
            const fw = Java.use("java.io.FileWriter").$new(filePath, true); // Append mode
            fw.write(`[${new Date().toISOString()}] 키워드 매치: ${data} (주소: ${address})\n`);
            fw.close();
            console.log(`[+] 민감 데이터 로그 저장 완료: ${filePath}`);
        } catch (err) {
            console.error(`[!] 로그 저장 실패: ${err.message}`);
        }
    }

    // ======================
    // 5. 실시간 UI 알림
    // ======================
    function alertUser(message) {
        Java.scheduleOnMainThread(function () {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            // 중첩 클래스는 외부 클래스의 속성이 아니라 $ 이름으로 직접 로드해야 함
            const Builder = Java.use("android.app.AlertDialog$Builder");

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
    let TargetClass;
    try {
        TargetClass = Java.use("com.example.app.TargetClass"); // 자리표시자: 실제 앱 클래스명으로 교체 필요
    } catch (e) {
        console.log("[-] com.example.app.TargetClass를 찾을 수 없습니다. 메서드 추적은 건너뜁니다.");
        TargetClass = null;
    }
    if (TargetClass) TargetClass.targetMethod.implementation = function (arg1) {
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
