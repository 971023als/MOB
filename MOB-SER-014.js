Java.perform(function () {
    console.log("[*] 운영체제 명령 실행 점검 시작...");

    // Runtime 클래스 및 exec() 메서드 후킹
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (command) {
        console.log(`[+] 명령 실행 감지: ${command}`);

        // 1. 실행 명령 검증
        if (isDangerousCommand(command)) {
            console.warn(`[!] 위험한 명령어 감지: ${command}`);
            blockCommand(command);
            return null;
        }

        // 2. 로그 저장
        saveLog(command);

        // 원래 명령 실행
        return this.exec(command);
    };

    // ====================================================
    // 1. 위험 명령 검증 함수
    // ====================================================
    function isDangerousCommand(command) {
        // 차단할 명령어 리스트 (확장 가능)
        const dangerousCommands = ["rm -rf", "wget", "curl", "nc", "bash", "sh"];
        return dangerousCommands.some(dangerous => command.includes(dangerous));
    }

    // ====================================================
    // 2. 명령 차단 함수
    // ====================================================
    function blockCommand(command) {
        console.error(`[X] 차단된 명령: ${command}`);
        alertUser("위험한 명령어 실행이 차단되었습니다.");
    }

    // ====================================================
    // 3. 로그 저장 함수
    // ====================================================
    function saveLog(command) {
        console.log(`[LOG] 실행 명령 저장: ${command}`);
        // 필요 시 서버 또는 로컬 파일로 저장 가능
    }

    // ====================================================
    // 4. 사용자 경고
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

    console.log("[*] 운영체제 명령 실행 점검 준비 완료.");
});
