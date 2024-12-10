Java.perform(function () {
    console.log("[*] 이용자 입력정보 보호 점검 및 테스트 시작...");

    // ======================
    // 1. 입력 정보 관리 클래스
    // ======================
    const EditText = Java.use("android.widget.EditText"); // 사용자 입력 위젯 클래스
    const InputConnection = Java.use("android.view.inputmethod.InputConnection"); // 입력 메서드 연결 클래스

    // ===========================================
    // 2. EditText.getText() 후킹
    // ===========================================
    EditText.getText.implementation = function () {
        const inputText = this.getText().toString();
        console.log(`[+] getText 호출됨 - 입력된 값: ${inputText}`);

        // 민감한 정보 입력 여부 감지
        if (inputText.includes("password") || inputText.includes("pin") || inputText.includes("account")) {
            console.log("[!] 민감한 정보가 입력됨 - 입력값 보호 확인 필요");
        } else {
            console.log("[+] 일반 정보 입력 감지");
        }

        return this.getText();
    };

    // ===========================================
    // 3. EditText.setText() 후킹
    // ===========================================
    EditText.setText.overload('java.lang.CharSequence').implementation = function (text) {
        console.log(`[+] setText 호출됨 - 설정 값: ${text}`);

        // 입력 보호 범위 확인
        if (text.toString().includes("password") || text.toString().includes("pin")) {
            console.log("[!] 민감한 입력값이 설정됨 - 보호 로직 확인 필요");
        }

        // 원래 동작 수행
        return this.setText(text);
    };

    // ===========================================
    // 4. InputConnection 관련 보호 점검
    // ===========================================
    InputConnection.commitText.implementation = function (text, newCursorPosition) {
        console.log(`[+] commitText 호출됨 - 입력된 값: ${text}`);

        // 입력값 보호 범위 확인
        if (text.toString().includes("password") || text.toString().includes("pin")) {
            console.log("[!] 민감한 입력값이 전송됨 - 보호 로직 점검 필요");
        }

        // 원래 동작 수행
        return this.commitText(text, newCursorPosition);
    };

    // ===========================================
    // 5. 입력 보호 절차 확인
    // ===========================================
    const SecureEditText = Java.use("com.example.security.SecureEditText"); // 보안 입력 필드 클래스 가정
    SecureEditText.isInputProtected.implementation = function () {
        const result = this.isInputProtected();
        console.log(`[+] isInputProtected 호출됨 - 입력 보호 상태: ${result ? "보호됨" : "보호되지 않음"}`);

        // 보호되지 않은 상태 감지
        if (!result) {
            console.log("[!] 입력 정보 보호 미적용 감지 - 보호 로직 점검 필요");
        }

        return result;
    };

    console.log("[*] 이용자 입력정보 보호 점검 및 테스트 완료.");
});
