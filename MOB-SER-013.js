Java.perform(function () {
    console.log("[*] 쿠키 변조 점검 시작...");

    const CookieManager = Java.use("android.webkit.CookieManager");

    // ====================================================
    // 1. 쿠키 설정 (setCookie) 후킹
    // ====================================================
    CookieManager.setCookie.overload("java.lang.String", "java.lang.String").implementation = function (url, value) {
        console.log(`[+] 쿠키 설정 감지: URL=${url}, Value=${value}`);
        
        // 쿠키 내용 검증
        if (isSensitiveData(value)) {
            console.warn(`[!] 민감한 쿠키 데이터 감지: ${value}`);
            alertUser("민감한 쿠키 데이터가 발견되었습니다. 보안 검토가 필요합니다.");
        }

        // 변조 테스트를 위해 쿠키 수정
        const modifiedValue = manipulateCookie(value);
        console.log(`[+] 쿠키 수정됨: ${modifiedValue}`);

        return this.setCookie(url, modifiedValue);
    };

    // ====================================================
    // 2. 쿠키 가져오기 (getCookie) 후킹
    // ====================================================
    CookieManager.getCookie.overload("java.lang.String").implementation = function (url) {
        const cookie = this.getCookie(url);
        console.log(`[+] 쿠키 가져오기 감지: URL=${url}, Cookie=${cookie}`);

        // 쿠키 내용 분석
        if (isWeakCookie(cookie)) {
            console.warn(`[!] 취약한 쿠키 감지: ${cookie}`);
        }

        return cookie;
    };

    // ====================================================
    // 3. 민감한 데이터 검증 함수
    // ====================================================
    function isSensitiveData(cookieValue) {
        // 예: 계정 정보, 인증 ID, 권한 구분자 등이 포함된 경우
        const sensitiveKeywords = ["auth", "token", "session", "admin", "userId"];
        return sensitiveKeywords.some(keyword => cookieValue.toLowerCase().includes(keyword));
    }

    // ====================================================
    // 4. 쿠키 변조 테스트
    // ====================================================
    function manipulateCookie(cookieValue) {
        // 테스트를 위한 쿠키 값 변조
        if (cookieValue.includes("userId")) {
            return cookieValue.replace(/userId=\d+/g, "userId=9999");
        }
        return cookieValue;
    }

    // ====================================================
    // 5. 약한 쿠키 검증 함수
    // ====================================================
    function isWeakCookie(cookieValue) {
        // 규칙성 검사 (예: 단순 숫자 증가, 짧은 길이 등)
        if (cookieValue.length < 10 || /^\d+$/.test(cookieValue)) {
            return true;
        }
        return false;
    }

    // ====================================================
    // 6. 사용자 경고
    // ====================================================
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

    console.log("[*] 쿠키 변조 점검 준비 완료.");
});
