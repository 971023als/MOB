Java.perform(function () {
    console.log("[*] 단말기 내 중요정보 저장 여부 점검 시작...");

    // ======================
    // 1. 중요 정보 키워드 정의
    // ======================
    const sensitiveKeywords = [
        "주민등록번호", "비밀번호", "OTP", "보안카드", "카드번호", "password",
        "cardnumber", "otp", "securitycard", "ssn" // 민감한 데이터 키워드
    ];

    const monitoredPaths = [
        "/data/data/com.example.app/files/",
        "/storage/emulated/0/Download/",
        "/sdcard/"
    ]; // 점검 대상 경로

    // ======================
    // 2. 파일 쓰기 감지
    // ======================
    const FileOutputStream = Java.use("java.io.FileOutputStream");

    FileOutputStream.write.overload("[B", "int", "int").implementation = function (b, off, len) {
        const stackTrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        const data = byteArrayToString(b, off, len);

        console.log(`[+] 파일에 데이터 쓰기 감지 (길이: ${len} bytes)`);
        console.log(`    - 데이터 내용 (미리보기): ${data.substring(0, 100)}`);
        console.log(`    - 호출 스택: ${stackTrace}`);

        if (containsSensitiveData(data)) {
            console.warn("[!] 경고: 민감한 정보가 파일에 저장될 가능성 감지!");
            alertUser("민감한 데이터가 파일에 저장될 수 있습니다.");
        }

        return this.write(b, off, len);
    };

    // ======================
    // 3. 파일 읽기 감지
    // ======================
    const FileInputStream = Java.use("java.io.FileInputStream");

    FileInputStream.read.overload("[B", "int", "int").implementation = function (b, off, len) {
        const bytesRead = this.read(b, off, len);
        const data = byteArrayToString(b, off, bytesRead);

        console.log(`[+] 파일에서 데이터 읽기 감지 (길이: ${bytesRead} bytes)`);
        console.log(`    - 데이터 내용 (미리보기): ${data.substring(0, 100)}`);

        if (containsSensitiveData(data)) {
            console.warn("[!] 경고: 민감한 정보가 파일에서 읽혔을 가능성 감지!");
            alertUser("파일에서 민감한 데이터가 읽혔습니다.");
        }

        return bytesRead;
    };

    // ======================
    // 4. 헬퍼 함수: 데이터 문자열 변환
    // ======================
    function byteArrayToString(byteArray, offset, length) {
        const buffer = Java.array('byte', byteArray).slice(offset, offset + length);
        return Java.use('java.lang.String').$new(buffer);
    }

    // ======================
    // 5. 헬퍼 함수: 민감한 데이터 포함 여부 확인
    // ======================
    function containsSensitiveData(data) {
        for (let keyword of sensitiveKeywords) {
            if (data.includes(keyword)) {
                return true;
            }
        }
        return false;
    }

    // ======================
    // 6. 실시간 경고 알림
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

    console.log("[*] 단말기 내 중요정보 저장 여부 점검 로직 설정 완료.");
});
