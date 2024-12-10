Java.perform(function () {
    console.log("[*] 부적절한 이용자 인가 여부 점검 시작...");

    // ======================
    // 1. 민감 데이터 필터링 키워드 설정
    // ======================
    const sensitiveKeywords = ["balance", "password", "token", "account", "userId"];

    // ======================
    // 2. 동적 파라미터 추출 변수
    // ======================
    let dynamicParams = new Set();

    // ======================
    // 3. 네트워크 요청 후킹 및 파라미터 추출
    // ======================
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const URL = Java.use("java.net.URL");

    HttpURLConnection.getInputStream.implementation = function () {
        console.log("[+] HTTP 요청 감지 - URL:");
        const url = this.getURL();
        console.log(`    - ${url}`);

        if (url.toString().includes("?")) {
            const originalUrl = url.toString();
            console.log(`[+] 원본 URL: ${originalUrl}`);

            // 파라미터 동적 추출
            const queryString = originalUrl.split("?")[1];
            const params = queryString.split("&");

            params.forEach(function (param) {
                const key = param.split("=")[0];
                dynamicParams.add(key); // 동적으로 파라미터 추가
                console.log(`[+] 동적 파라미터 추출: ${key}`);
            });

            // 동적 파라미터 테스트 (변조된 값 적용)
            dynamicParams.forEach(function (param) {
                const regex = new RegExp(`${param}=\\w+`, "g");
                if (regex.test(originalUrl)) {
                    const manipulatedUrl = originalUrl.replace(regex, `${param}=testValue`);
                    console.log(`[!] 테스트: ${param} 변조 URL: ${manipulatedUrl}`);

                    // 요청 URL을 변조된 값으로 설정
                    const newUrl = URL.$new(manipulatedUrl);
                    this.url = newUrl;

                    // 요청 수행 및 응답 분석
                    const response = this.getInputStream();
                    analyzeResponse(response);
                }
            });
        }

        return this.getInputStream();
    };

    // ======================
    // 4. 서버 응답 자동 분석 및 민감 데이터 필터링
    // ======================
    function analyzeResponse(response) {
        const responseStr = response.toString();
        console.log(`[+] 서버 응답 분석: ${responseStr}`);

        // 민감 데이터 키워드 필터링
        sensitiveKeywords.forEach(function (keyword) {
            if (responseStr.includes(keyword)) {
                console.log(`[!] 경고: 민감 데이터 감지 - 키워드: ${keyword}`);
                alertUser(`민감 데이터 감지됨: 키워드 '${keyword}' 발견!`);
            }
        });

        // 권한 검증 여부 확인
        if (responseStr.includes("Unauthorized") || responseStr.includes("Forbidden")) {
            console.log("[+] 권한 검증 성공: 접근 차단됨");
        } else {
            console.log("[+] 정상 응답 처리됨.");
        }
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

    console.log("[*] 부적절한 이용자 인가 여부 점검 확장 완료.");
});
