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
    const PasswordResetManager = Java.use("com.example.app.PasswordResetManager"); // 비밀번호 초기화 클래스 (예시)

    PasswordResetManager.resetPassword.implementation = function (userId) {
        const newPassword = this.resetPassword(userId); // 기존 로직 호출
        console.log(`[+] 초기화된 비밀번호: ${newPassword} (사용자 ID: ${userId})`);

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
            console.log(`[+] 새로운 초기화 비밀번호 저장: ${newPassword}`);
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
            const AlertDialog = Java.use("android.app.AlertDialog");
            const Builder = AlertDialog.Builder;

            const builder = Builder.$new(context);
            builder.setTitle("보안 경고");
            builder.setMessage(message);
            builder.setPositiveButton("확인", null);
            builder.show();
        });
    }

    console.log("[*] 유추 가능한 초기화 비밀번호 점검 로직 설정 완료.");
});
