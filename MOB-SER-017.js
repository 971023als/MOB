Java.perform(function () {
    console.log("[*] LDAP Injection 탐지 및 방지 스크립트 실행 중...");

    // LDAP 쿼리 생성에 사용되는 클래스 및 메서드 후킹
    const LDAPContext = Java.use("javax.naming.directory.DirContext");

    // search() 메서드 후킹
    LDAPContext.search.overload("java.lang.String", "java.lang.String", "[Ljava.lang.Object;", "javax.naming.directory.SearchControls").implementation = function (base, filter, args, controls) {
        console.log("[+] LDAP search() 호출 감지");

        // 필터에 의심스러운 특수문자 포함 여부 확인
        if (isInjectionDetected(filter)) {
            console.warn(`[!] LDAP Injection 의심 필터: ${filter}`);
            alertUser(`LDAP Injection 의심 요청 차단: ${filter}`);
            throw new Error("LDAP Injection 의심 요청 차단");
        }

        // 원래의 메서드 호출
        return this.search(base, filter, args, controls);
    };

    // ====================================================
    // 1. Injection 탐지 함수
    // ====================================================
    function isInjectionDetected(filter) {
        const suspiciousChars = ["=", "+", "<", ">", "#", ";", "/"];
        for (let i = 0; i < suspiciousChars.length; i++) {
            if (filter.includes(suspiciousChars[i])) {
                return true;
            }
        }
        return false;
    }

    // ====================================================
    // 2. 사용자 경고 함수
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

    console.log("[*] LDAP Injection 탐지 및 방지 준비 완료.");
});
