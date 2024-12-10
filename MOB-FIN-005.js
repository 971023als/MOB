Java.perform(function () {
    console.log("[*] 전자금융 거래정보 재사용 검증 후킹 시작...");

    // ======================
    // 1. 거래정보 관련 클래스 및 메서드
    // ======================
    const TransactionManager = Java.use("com.example.bank.TransactionManager"); // 거래 관리 클래스
    const TransactionCache = {}; // 이미 사용된 거래 정보를 저장할 캐시

    // ===========================================
    // 2. 거래정보 검증 및 재사용 감지
    // ===========================================
    TransactionManager.processTransaction.implementation = function (transactionId, transactionData) {
        console.log(`[+] processTransaction 호출됨 - 거래 ID: ${transactionId}`);
        console.log(`[+] 거래 데이터: ${transactionData}`);

        // 이미 사용된 거래 ID인지 확인
        if (TransactionCache[transactionId]) {
            console.log(`[!] 재사용 감지: 거래 ID ${transactionId}는 이미 처리된 거래입니다.`);
            return false; // 재사용 거래 차단
        }

        // 거래 데이터를 기준으로 재사용 여부 확인
        const transactionHash = generateHash(transactionData);
        if (TransactionCache[transactionHash]) {
            console.log(`[!] 재사용 감지: 동일한 거래 데이터가 이미 처리되었습니다.`);
            return false; // 재사용 데이터 차단
        }

        // 원래 동작 수행
        const result = this.processTransaction(transactionId, transactionData);
        console.log(`[+] 거래 처리 결과: ${result}`);

        // 처리 완료된 거래 정보를 캐시에 저장
        TransactionCache[transactionId] = true;
        TransactionCache[transactionHash] = true;
        return result;
    };

    // ===========================================
    // 3. 거래 데이터 해시 생성 함수
    // ===========================================
    function generateHash(data) {
        const crypto = Java.use("java.security.MessageDigest");
        const charset = Java.use("java.nio.charset.StandardCharsets").UTF_8;
        const digest = crypto.getInstance("SHA-256");
        const byteArray = digest.digest(data.toString().getBytes(charset));
        const hash = byteArray.map(b => (b & 0xFF).toString(16).padStart(2, "0")).join("");
        console.log(`[+] 거래 데이터 해시 생성됨: ${hash}`);
        return hash;
    }

    // ===========================================
    // 4. 테스트를 위한 재사용 조건 처리
    // ===========================================
    TransactionManager.simulateDuplicateTransaction.implementation = function (transactionId, transactionData) {
        console.log(`[+] simulateDuplicateTransaction 호출됨 - 거래 ID: ${transactionId}`);
        console.log(`[+] 거래 데이터: ${transactionData}`);

        if (TransactionCache[transactionId]) {
            console.log(`[!] 테스트: 재사용 거래 ID 감지 → 차단 처리`);
            return false;
        }

        const transactionHash = generateHash(transactionData);
        if (TransactionCache[transactionHash]) {
            console.log(`[!] 테스트: 재사용 거래 데이터 감지 → 차단 처리`);
            return false;
        }

        console.log(`[+] 테스트: 재사용 거래가 정상 처리됨 → 보안 취약점 가능성`);
        return true; // 테스트 목적으로 정상 처리
    };

    console.log("[*] 전자금융 거래정보 재사용 검증 후킹 완료.");
});
