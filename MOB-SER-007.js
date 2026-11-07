Java.perform(function () {
    console.log("[*] 유추 가능한 초기화 비밀번호 점검 시작...");

    // ======================
    // 1. 비밀번호 생성 규칙 점검
    // ======================
    const resetPasswordPatterns = [
        /^[0-9]{6}$/, // 6자리 숫자만
        /^[a-zA-Z0-9]{8}$/, // 8자리 영숫자
        /^(password|123456|qwerty)$/, // 흔히 사용되는 비밀번호
    ];

    let generatedPasswords = new Set(); // 생성된 초기화 비밀번호 저장

    // ======================
    // 2. 비밀번호 초기화 로직 후킹
    // ======================

    // 민감정보 평문 로깅 방지: 값 대신 길이만 남긴다
    function mask(value) {
        if (value === null || value === undefined) return "(null)";
        return "***" + "(len=" + value.toString().length + ")";
    }

    const PasswordResetManager = Java.use("com.example.app.PasswordResetManager"); // 비밀번호 초기화 클래스 (예시)

    PasswordResetManager.resetPassword.implementation = function (userId) {
        const newPassword = this.resetPassword(userId); // 기존 로직 호출
        console.log(`[+] 초기화된 비밀번호: ${mask(newPassword)} (사용자 ID: ${userId})`);

        if (isPasswordPredictable(newPassword)) {
            console.log("[!] 경고: 유추 가능한 초기화 비밀번호 생성 감지!");
            alertUser("유추 가능한 초기화 비밀번호가 생성되었습니다.");
        } else {
            console.log("[+] 초기화 비밀번호 규칙성 문제 없음.");
        }

        if (generatedPasswords.has(newPassword)) {
            console.log("[!] 경고: 동일한 초기화 비밀번호가 중복 생성됨!");
        } else {
            generatedPasswords.add(newPassword);
            console.log("[+] 새로운 초기화 비밀번호 저장 (값은 마스킹됨)");
        }

        return newPassword;
    };

    // ======================
    // 3. 비밀번호 규칙성 점검 함수
    // ======================
    function isPasswordPredictable(password) {
        for (let pattern of resetPasswordPatterns) {
            if (pattern.test(password)) {
                return true; // 규칙에 일치하면 예측 가능
            }
        }
        return false; // 예측 불가능한 비밀번호
    }

    // ======================
    // 4. 실시간 경고 알림
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

    console.log("[*] 유추 가능한 초기화 비밀번호 점검 로직 설정 완료.");
});
