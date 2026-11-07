Java.perform(function () {
    console.log("[*] 파일 다운로드 보안 검사 시작...");

    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const Thread = Java.use("java.lang.Thread");

    // true로 바꾸면 허용 목록 밖 다운로드를 예외로 차단한다. 기본값 false(탐지만).
    const BLOCK_DISALLOWED_DOWNLOADS = false;
    // true로 바꾸면 다운로드 로그를 외부 서버로 전송한다. 기본값 false(로컬 저장만).
    const ENABLE_REMOTE_LOG_UPLOAD = false;

    HttpURLConnection.getInputStream.implementation = function () {
        const connection = this;
        const inputStream = this.getInputStream.call(this);
        const targetUrl = connection.getURL().toString();
        const fileSize = connection.getContentLength();

        console.log(`[+] 요청 URL: ${targetUrl}`);
        console.log(`[+] 파일 크기: ${fileSize} bytes`);

        // 파일 다운로드 허용 여부 검사
        if (!isAllowedFile(targetUrl, fileSize, connection)) {
            console.warn("[!] 허용되지 않은 파일 다운로드 감지");
            alertUser(`허용되지 않은 다운로드 감지: ${targetUrl}`);
            if (BLOCK_DISALLOWED_DOWNLOADS) {
                throw new Error("다운로드가 허용되지 않은 파일입니다.");
            }
        }

        // 속도 제한 적용
        const limitedStream = limitDownloadSpeed(inputStream, fileSize);

        // [결정 필요] 외부 로그 서버 전송은 기본 비활성.
        // 앱 사용자의 다운로드 URL을 외부로 보내는 행위이므로 켜기 전에 목적·수신 서버를 합의해야 한다.
        if (ENABLE_REMOTE_LOG_UPLOAD) {
            sendLogToServer(targetUrl, fileSize);
        } else {
            saveLogLocally(JSON.stringify({
                timestamp: new Date().toISOString(),
                url: targetUrl,
                fileSize: fileSize,
                action: "DOWNLOAD_ATTEMPT"
            }));
        }

        return limitedStream;
    };

    // ======================
    // 1. 파일 차단 조건 확장
    // ======================
    const allowedExtensions = [".jpg", ".png", ".pdf"];
    const allowedFileNames = ["terms_of_service.pdf", "privacy_policy.pdf"];
    const maxAllowedSize = 10 * 1024 * 1024; // 10MB 제한

    function isAllowedFile(url, size, connection) {
        // 확장자 검사
        for (let ext of allowedExtensions) {
            if (url.endsWith(ext)) {
                console.log(`[+] 허용된 확장자: ${ext}`);
                return size <= maxAllowedSize; // 파일 크기 제한 검사
            }
        }

        // 파일 이름 검사
        for (let fileName of allowedFileNames) {
            if (url.includes(fileName)) {
                console.log(`[+] 허용된 파일 이름: ${fileName}`);
                return size <= maxAllowedSize;
            }
        }

        // 헤더 검사 (예: Content-Type)
        const contentType = connection.getContentType();
        if (contentType && (contentType.startsWith("application/pdf") || contentType.startsWith("image/"))) {
            console.log(`[+] 허용된 Content-Type: ${contentType}`);
            return size <= maxAllowedSize;
        }

        console.warn(`[!] 차단된 파일 조건: URL=${url}, 크기=${size}, Content-Type=${contentType}`);
        return false;
    }

    // ======================
    // 2. 속도 제한
    // ======================
    function limitDownloadSpeed(inputStream, fileSize) {
        const ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
        // 기존 코드는 길이 0 버퍼로 read()를 호출해 영원히 0만 반환되는 무한 루프였다.
        const buffer = Java.array("byte", new Array(8192).fill(0));
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        const collected = ByteArrayOutputStream.$new();
        let bytesRead = 0;

        // 동적 속도 설정
        const delay = fileSize > 5 * 1024 * 1024 ? 100 : 50; // 5MB 이상 파일은 느리게 다운로드
        console.log(`[+] 속도 제한: ${delay}ms per read`);

        while ((bytesRead = inputStream.read(buffer)) !== -1) {
            collected.write(buffer, 0, bytesRead);
            Thread.sleep(delay);
        }

        return ByteArrayInputStream.$new(collected.toByteArray());
    }

    // ======================
    // 3. 로그 중앙 저장 (RSA 암호화)
    // ======================
    function sendLogToServer(url, fileSize) {
        const logServerUrl = "http://central-log-server.example.com/upload-log";

        const jsonData = JSON.stringify({
            timestamp: new Date().toISOString(),
            url: url,
            fileSize: fileSize,
            action: "DOWNLOAD_ATTEMPT"
        });

        try {
            const encryptedData = encryptLogData(jsonData);

            const OkHttpClient = Java.use("okhttp3.OkHttpClient");
            const Request = Java.use("okhttp3.Request");
            const MediaType = Java.use("okhttp3.MediaType");
            const RequestBody = Java.use("okhttp3.RequestBody");

            const client = OkHttpClient.$new();
            const mediaType = MediaType.parse("application/json");
            const body = RequestBody.create(mediaType, encryptedData);
            const request = Request.Builder.$new()
                .url(logServerUrl)
                .post(body)
                .build();

            const response = client.newCall(request).execute();
            console.log("[+] 로그 중앙 저장 성공:", response.code());
        } catch (err) {
            console.error("[!] 로그 중앙 저장 실패, 로컬에 임시 저장합니다:", err.message);
            saveLogLocally(jsonData); // 실패 시 로컬 저장
        }
    }

    function encryptLogData(data) {
        const KeyFactory = Java.use("java.security.KeyFactory");
        const X509EncodedKeySpec = Java.use("java.security.spec.X509EncodedKeySpec");
        const Cipher = Java.use("javax.crypto.Cipher");
        const Base64 = Java.use("android.util.Base64");

        // RSA 공개키 (PEM 형식에서 가져온 키)
        // [주의] 아래 키는 중간이 잘린 자리표시자라 generatePublic이 실패한다.
        // ENABLE_REMOTE_LOG_UPLOAD를 켜기 전에 실제 로그 서버의 공개키로 교체해야 한다.
        const publicKeyString = `
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvrC7O...
            -----END PUBLIC KEY-----
        `;

        // PEM 키 처리
        const publicKeyBytes = Base64.decode(publicKeyString.replace(/(-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n)/g, ""), 0);
        const keySpec = X509EncodedKeySpec.$new(publicKeyBytes);
        const keyFactory = KeyFactory.getInstance("RSA");
        const publicKey = keyFactory.generatePublic(keySpec);

        const cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        const encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.encodeToString(encryptedBytes, 0);
    }

    function saveLogLocally(logData) {
        const fileName = `/data/local/tmp/download_log_${new Date().getTime()}.txt`;
        const file = Java.use("java.io.File").$new(fileName);
        const FileWriter = Java.use("java.io.FileWriter");

        try {
            const writer = FileWriter.$new(file);
            writer.write(logData);
            writer.close();
            console.log(`[+] 로그 로컬 저장 완료: ${fileName}`);
        } catch (err) {
            console.error("[!] 로그 로컬 저장 실패:", err.message);
        }
    }

    // ======================
    // 4. 실시간 UI 알림
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

    console.log("[*] 파일 다운로드 보안 검사 완료.");
});
