Java.perform(function () {
    console.log("[*] 이용자 인증정보 재사용 여부 점검 시작...");

    // ======================
    // 1. 중요 인증정보 추적 변수
    // ======================
    let usedAuthValues = new Set(); // 이미 사용된 인증정보를 저장

    // ======================
    // 2. 인증 요청 후킹
    // ======================
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const URL = Java.use("java.net.URL");

    HttpURLConnection.getOutputStream.implementation = function () {
        const url = this.getURL();
        console.log(`[+] 인증 요청 감지 - URL: ${url}`);

        const outputStream = this.getOutputStream();
        const originalData = readStreamData(outputStream);

        console.log(`[+] 요청 데이터: ${originalData}`);

        // 인증 값 추출 (예: OTP, 전자서명, SMS 코드)
        const authValue = extractAuthValue(originalData);
        if (authValue) {
            console.log(`[+] 인증 값 추출: ${authValue}`);

            if (usedAuthValues.has(authValue)) {
                console.log(`[!] 경고: 인증 값 재사용 시도 감지 - ${authValue}`);
                alertUser("이미 사용된 인증 값이 재사용되고 있습니다!");
            } else {
                usedAuthValues.add(authValue);
                console.log(`[+] 인증 값 저장: ${authValue}`);
            }
        }

        return outputStream;
    };

    // ======================
    // 3. 인증 응답 후킹
    // ======================
    HttpURLConnection.getInputStream.implementation = function () {
        const response = this.getInputStream();
        const responseData = readStreamData(response);

        console.log(`[+] 인증 응답 데이터: ${responseData}`);

        // 응답에서 민감 데이터 확인
        analyzeResponse(responseData);

        return response;
    };

    // ======================
    // 4. 데이터 스트림 읽기
    // ======================
    function readStreamData(stream) {
        try {
            const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            const BufferedReader = Java.use("java.io.BufferedReader");

            const baos = ByteArrayOutputStream.$new();
            let b;
            while ((b = stream.read()) !== -1) {
                baos.write(b);
            }
            return baos.toString("UTF-8");
        } catch (err) {
            console.error(`[!] 데이터 스트림 읽기 오류: ${err.message}`);
            return null;
        }
    }

    // ======================
    // 5. 인증 값 추출 함수
    // ======================
    function extractAuthValue(data) {
        // 인증 값이 JSON 데이터로 포함된 경우
        const regex = /"authValue"\s*:\s*"(\w+)"/; // 예시: {"authValue": "123456"}
        const match = regex.exec(data);
        return match ? match[1] : null;
    }

    // ======================
    // 6. 응답 데이터 분석
    // ======================
    function analyzeResponse(data) {
        if (data.includes("success") || data.includes("approved")) {
            console.log("[+] 인증 성공 응답 확인.");
        } else if (data.includes("error") || data.includes("denied")) {
            console.log("[!] 인증 실패 응답 감지.");
        }
    }

    // ======================
    // 7. 실시간 경고 알림
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

    console.log("[*] 이용자 인증정보 재사용 여부 점검 완료.");
});
