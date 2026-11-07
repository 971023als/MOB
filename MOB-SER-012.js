Java.perform(function () {
    console.log("[*] 세션 ID 복잡성 점검 시작...");

    const UUID = Java.use("java.util.UUID");
    const SecureRandom = Java.use("java.security.SecureRandom");

    // ====================================================
    // 1. 세션 ID 생성 과정 추적 및 복잡성 확인
    // ====================================================
    UUID.randomUUID.implementation = function () {
        const sessionId = this.randomUUID();
        // 반환값은 Java UUID 객체이므로 문자열로 변환해야 길이·패턴 검사가 동작한다
        const sessionIdStr = sessionId.toString();
        console.log(`[+] UUID 생성됨: ${sessionIdStr}`);

        // 세션 ID 패턴 분석
        if (isWeakSessionID(sessionIdStr)) {
            console.warn(`[!] 약한 세션 ID 감지: ${sessionIdStr}`);
            alertUser("약한 세션 ID가 생성되었습니다. 복잡성을 강화하세요.");
        }

        return sessionId;
    };

    SecureRandom.nextBytes.overload("[B").implementation = function (bytes) {
        this.nextBytes(bytes);
        const generatedBytes = Java.array('byte', bytes);

        console.log(`[+] SecureRandom 데이터 생성됨: ${generatedBytes}`);
    };

    // ====================================================
    // 2. 세션 ID의 규칙성 분석
    // ====================================================
    function isWeakSessionID(sessionId) {
        // 간단한 규칙성을 탐지 (예: 숫자 증가, 반복되는 패턴 등)
        const regexSimplePattern = /^(\d+)$|([a-zA-Z])\1{3,}$/;
        if (regexSimplePattern.test(sessionId)) {
            return true; // 단순 패턴 탐지
        }

        // 길이 체크 (복잡성이 낮은 경우)
        if (sessionId.length < 16) {
            console.log(`[!] 세션 ID 길이가 너무 짧음: ${sessionId.length}`);
            return true;
        }

        return false;
    }

    // ====================================================
    // 3. 사용자 경고 및 로그 저장
    // ====================================================
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

    console.log("[*] 세션 ID 복잡성 점검 완료.");
});
