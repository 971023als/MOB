Java.perform(function () {
    console.log("[*] 시스템 운영 정보 노출 여부 점검 시작...");

    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const URL = Java.use("java.net.URL");

    // ================================
    // 1. HTTP 요청 모니터링 및 로그 검사
    // ================================
    HttpURLConnection.getInputStream.implementation = function () {
        const connection = this;
        const inputStream = this.getInputStream.call(this);
        const targetUrl = connection.getURL().toString();

        console.log(`[+] 요청 URL: ${targetUrl}`);

        // 민감 정보 노출 검사
        if (isSensitiveDataExposed(targetUrl)) {
            console.warn(`[!] 민감한 운영 정보가 외부 URL에 노출됨: ${targetUrl}`);
            logSensitiveExposure(targetUrl);
            alertUser(`경고: 민감한 정보가 ${targetUrl}에 노출되었습니다.`);
        }

        return inputStream;
    };

    // ====================================
    // 2. 검색 엔진을 통한 노출 정보 탐지
    // ====================================
    const knownSearchEngines = [
        "google.com", "bing.com", "yahoo.com", "baidu.com", "duckduckgo.com"
    ];

    function isSensitiveDataExposed(url) {
        // 검색 엔진 URL 패턴 확인
        for (let engine of knownSearchEngines) {
            if (url.includes(engine)) {
                console.log(`[!] 검색 엔진에 노출된 URL: ${url}`);
                return true;
            }
        }

        // URL에 민감한 키워드 포함 여부 검사
        const sensitiveKeywords = ["config", "admin", "password", "backup", "internal"];
        for (let keyword of sensitiveKeywords) {
            if (url.toLowerCase().includes(keyword)) {
                console.log(`[!] 민감한 키워드(${keyword})가 URL에 포함됨: ${url}`);
                return true;
            }
        }

        return false;
    }

    // ======================
    // 3. 로그 기록 및 알림
    // ======================
    function logSensitiveExposure(url) {
        const logMessage = `민감한 정보 노출 감지: ${url}`;
        console.log(`[+] 로그 저장: ${logMessage}`);
        saveLogToFile(logMessage);
    }

    function saveLogToFile(message) {
        const File = Java.use("java.io.File");
        const FileWriter = Java.use("java.io.FileWriter");

        const fileName = `/data/local/tmp/sensitive_exposure_${new Date().getTime()}.log`;
        const file = File.$new(fileName);
        const writer = FileWriter.$new(file);

        try {
            writer.write(message);
            writer.close();
            console.log(`[+] 로그 파일 저장 완료: ${fileName}`);
        } catch (err) {
            console.error(`[!] 로그 파일 저장 실패: ${err.message}`);
        }
    }

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

    console.log("[*] 시스템 운영 정보 노출 여부 점검 완료.");
});
