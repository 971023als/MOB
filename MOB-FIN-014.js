Java.perform(function () {
    console.log("[*] 사용자 요청 차단 및 네트워크 응답 조작 (상태 분석 포함) 시작...");

    // ======================
    // 1. 사용자 요청 차단 로직 확장 (상태 분석 추가)
    // ======================
    const SecurityManager = Java.use("com.example.security.SecurityManager"); // 보안 프로그램 관리 클래스
    const AlertDialog = Java.use("android.app.AlertDialog"); // Android 경고 대화상자 클래스

    SecurityManager.disable.implementation = function () {
        console.log("[*] disable 호출됨");

        // 사용자 로그 기록
        const username = this.getCurrentUser(); // 현재 사용자를 가져오는 메서드 가정
        console.log(`[!] 사용자 ${username}가 보안 프로그램 해제를 시도함`);

        // 사용자 상태 분석 및 분기 처리
        if (username === "testuser") {
            console.log(`[!] 테스트 사용자 ${username}의 요청 차단`);
            this.logEvent("Unauthorized disable attempt", username); // 로그 기록 (가상의 메서드)
            console.log("[+] 사용자 상태: 테스트 계정으로 요청 차단");

            // 사용자 경고 대화상자 출력
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const builder = AlertDialog.Builder.$new(context);
            builder.setTitle("경고");
            builder.setMessage("보안 프로그램 해제는 허용되지 않습니다.");
            builder.setPositiveButton("확인", null);
            builder.show();

            return false; // 요청 차단
        } else if (username === "admin") {
            console.log(`[!] 관리자 계정(${username})의 요청 감지`);
            console.log("[+] 사용자 상태: 관리자 계정으로 요청 허용");
        } else {
            console.log(`[!] 일반 사용자(${username})의 요청 감지`);
            console.log("[+] 사용자 상태: 추가 검증 없이 요청 진행");
        }

        console.log("[+] 사용자 요청 승인: 보안 프로그램 해제 요청 진행");
        return this.disable(); // 원래 동작 수행
    };

    // ======================
    // 2. 네트워크 응답 조작 테스트 (상태 분석 추가)
    // ======================
    const NetworkManager = Java.use("com.example.network.NetworkManager"); // 네트워크 관리 클래스

    NetworkManager.sendRequest.implementation = function (url, data) {
        console.log(`[+] sendRequest 호출됨 - URL: ${url}`);
        console.log(`[+] 요청 데이터: ${JSON.stringify(data)}`);

        // 원래 요청 수행
        const response = this.sendRequest(url, data);
        console.log(`[+] 원래 응답 데이터: ${response}`);

        // 응답 상태 분석 및 분기 처리
        if (url.includes("/disableSecurity")) {
            console.log("[!] 보안 프로그램 비활성화 요청에 대한 응답 감지");
            if (response.includes("status:approved")) {
                console.log("[+] 응답 상태: 비활성화 승인됨 (status:approved)");
                console.log("[!] 테스트: 응답을 비활성화 거부 상태로 변경");
                const modifiedResponse = response.replace("status:approved", "status:denied");
                console.log(`[+] 응답 데이터 변경됨: ${modifiedResponse}`);
                return modifiedResponse; // 응답 조작
            } else if (response.includes("status:denied")) {
                console.log("[+] 응답 상태: 비활성화 거부됨 (status:denied)");
            } else {
                console.log("[!] 알 수 없는 응답 상태 감지");
            }
        } else {
            console.log("[+] 일반 요청 - 응답 조작 없이 원래 응답 반환");
        }

        return response; // 원래 응답 반환
    };

    // ======================
    // 3. 사용자 로그 기록 함수 (가상)
    // ======================
    SecurityManager.logEvent.implementation = function (eventType, user) {
        console.log(`[+] 이벤트 로그 기록 - 유형: ${eventType}, 사용자: ${user}`);
        this.logEvent(eventType, user); // 원래 동작 수행
    };

    console.log("[*] 사용자 요청 차단 및 네트워크 응답 조작 (상태 분석 포함) 완료.");
});
