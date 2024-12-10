Java.perform(function () {
    console.log("[*] 접근매체 발급 시 실명확인 수행 여부 점검 시작...");

    // ======================
    // 1. 실명확인 관련 클래스 및 메서드 후킹
    // ======================
    const RealNameVerification = Java.use("com.example.app.RealNameVerification");
    const AccessMediaManager = Java.use("com.example.app.AccessMediaManager");

    // ======================
    // 2. 실명확인 메서드 후킹
    // ======================
    RealNameVerification.verifyIdentity.overload('java.lang.String', 'java.lang.String').implementation = function (id, method) {
        console.log(`[+] 실명확인 호출됨 - ID: ${id}, 인증방법: ${method}`);

        // 실명확인 방식 검증
        if (method === "ID_CARD" || method === "VIDEO_CALL") {
            console.log(`[+] 실명확인 방법: ${method} (적합)`);
        } else {
            console.log(`[!] 실명확인 방법: ${method} (부적합)`);
        }

        const result = this.verifyIdentity(id, method);
        console.log(`[+] 실명확인 결과: ${result ? "성공" : "실패"}`);
        return result;
    };

    // ======================
    // 3. 접근매체 발급 메서드 후킹
    // ======================
    AccessMediaManager.issueAccessMedia.overload('java.lang.String', 'java.lang.String').implementation = function (id, mediaType) {
        console.log(`[+] 접근매체 발급 호출됨 - ID: ${id}, 매체 유형: ${mediaType}`);

        // 실명확인 여부 확인
        const isVerified = RealNameVerification.verifyIdentity(id, "ID_CARD");
        if (!isVerified) {
            console.log("[!] 실명확인 없이 접근매체 발급 시도 감지!");
            throw new Error("실명확인 없이 접근매체 발급이 불가능합니다.");
        }

        const result = this.issueAccessMedia(id, mediaType);
        console.log(`[+] 접근매체 발급 결과: ${result ? "성공" : "실패"}`);
        return result;
    };

    console.log("[*] 접근매체 발급 시 실명확인 수행 여부 점검 완료.");
});
