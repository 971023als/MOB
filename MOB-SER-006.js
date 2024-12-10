Java.perform(function () {
    console.log("[*] 유추 가능한 인증정보 점검 시작...");

    // ======================
    // 1. 비밀번호 복잡도 점검 기준
    // ======================
    const complexityRules = {
        minLength: 8, // 최소 길이
        containsUppercase: true, // 대문자 포함 여부
        containsLowercase: true, // 소문자 포함 여부
        containsNumber: true, // 숫자 포함 여부
        containsSpecialChar: true, // 특수문자 포함 여부
        disallowedPatterns: [
            "1234", "abcd", "password", "admin", "qwerty", "0000", "1111", "user"
        ] // 유추 가능한 패턴
    };

    const personalInfo = [
        "01012345678", "900101", "1990", "exampleName" // 개인 신상정보 (예: 전화번호, 생년월일, 이름)
    ];

    // ======================
    // 2. 비밀번호 등록 및 변경 로직 후킹
    // ======================
    const PasswordManager = Java.use("com.example.app.PasswordManager"); // 예시 클래스 이름

    PasswordManager.registerPassword.implementation = function (password) {
        console.log(`[+] 비밀번호 등록 요청: ${password}`);

        if (!isPasswordComplex(password)) {
            console.log("[!] 경고: 비밀번호 복잡도 기준 미충족!");
            alertUser("비밀번호가 복잡도 기준을 충족하지 못했습니다.");
        } else {
            console.log("[+] 비밀번호 복잡도 기준 충족.");
        }

        if (isPasswordPredictable(password)) {
            console.log("[!] 경고: 유추 가능한 비밀번호 사용 감지!");
            alertUser("쉽게 유추 가능한 비밀번호가 사용되었습니다.");
        } else {
            console.log("[+] 유추 가능성 없음.");
        }

        return this.registerPassword(password);
    };

    PasswordManager.changePassword.implementation = function (oldPassword, newPassword) {
        console.log(`[+] 비밀번호 변경 요청: 기존 비밀번호 - ${oldPassword}, 새로운 비밀번호 - ${newPassword}`);

        if (!isPasswordComplex(newPassword)) {
            console.log("[!] 경고: 새로운 비밀번호가 복잡도 기준을 충족하지 못했습니다.");
            alertUser("새로운 비밀번호가 복잡도 기준을 충족하지 못했습니다.");
        } else {
            console.log("[+] 새로운 비밀번호 복잡도 기준 충족.");
        }

        if (isPasswordPredictable(newPassword)) {
            console.log("[!] 경고: 새로운 비밀번호가 유추 가능한 값입니다!");
            alertUser("새로운 비밀번호로 쉽게 유추 가능한 값이 사용되었습니다.");
        } else {
            console.log("[+] 새로운 비밀번호 유추 가능성 없음.");
        }

        return this.changePassword(oldPassword, newPassword);
    };

    // ======================
    // 3. 비밀번호 복잡도 점검 함수
    // ======================
    function isPasswordComplex(password) {
        if (password.length < complexityRules.minLength) return false;
        if (complexityRules.containsUppercase && !/[A-Z]/.test(password)) return false;
        if (complexityRules.containsLowercase && !/[a-z]/.test(password)) return false;
        if (complexityRules.containsNumber && !/[0-9]/.test(password)) return false;
        if (complexityRules.containsSpecialChar && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;

        return true;
    }

    // ======================
    // 4. 유추 가능성 점검 함수
    // ======================
    function isPasswordPredictable(password) {
        // 유추 가능한 패턴 검사
        for (let pattern of complexityRules.disallowedPatterns) {
            if (password.includes(pattern)) return true;
        }

        // 개인 신상정보 검사
        for (let info of personalInfo) {
            if (password.includes(info)) return true;
        }

        return false;
    }

    // ======================
    // 5. 실시간 경고 알림
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

    console.log("[*] 유추 가능한 인증정보 점검 로직 설정 완료.");
});
