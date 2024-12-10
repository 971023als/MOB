Java.perform(function () {
    // 대상 함수 후킹 설정
    var libc_printf = Module.findExportByName(null, 'printf');      // printf
    var libc_sprintf = Module.findExportByName(null, 'sprintf');    // sprintf
    var libc_fprintf = Module.findExportByName(null, 'fprintf');    // fprintf
    var libc_snprintf = Module.findExportByName(null, 'snprintf');  // snprintf

    // 사용자 입력에 특정 키워드나 값을 검사하기 위한 조건
    var suspiciousKeywords = ["password", "creditcard", "secret"]; // 민감 데이터 예시

    // 공통 로직: 포맷 문자열 점검 및 사용자 입력 분석
    function checkFormatString(functionName, formatString, args) {
        console.log(`[*] ${functionName} 호출 감지`);
        console.log(`    포맷 문자열: ${formatString}`);

        // 포맷 문자열에 위험 요소 탐지
        if (formatString.includes('%s') || formatString.includes('%x') || formatString.includes('%n')) {
            console.warn(`[!] ${functionName}에서 포맷 문자열 취약점 발견!`);
        }

        // 사용자 입력에 의심스러운 키워드 포함 여부 탐지
        for (var i = 1; i < args.length; i++) { // args[0]는 포맷 문자열
            var argValue = Memory.readUtf8String(args[i]);
            if (argValue) {
                suspiciousKeywords.forEach(function (keyword) {
                    if (argValue.includes(keyword)) {
                        console.error(`[!] ${functionName}: 민감 키워드(${keyword})가 포함된 입력 탐지!`);
                        console.error(`    입력값: ${argValue}`);
                    }
                });
            }
        }
    }

    // printf 후킹
    if (libc_printf) {
        Interceptor.attach(libc_printf, {
            onEnter: function (args) {
                var formatString = Memory.readUtf8String(args[0]);
                checkFormatString("printf", formatString, args);
            }
        });
    }

    // sprintf 후킹
    if (libc_sprintf) {
        Interceptor.attach(libc_sprintf, {
            onEnter: function (args) {
                var formatString = Memory.readUtf8String(args[0]);
                checkFormatString("sprintf", formatString, args);
            }
        });
    }

    // fprintf 후킹
    if (libc_fprintf) {
        Interceptor.attach(libc_fprintf, {
            onEnter: function (args) {
                var formatString = Memory.readUtf8String(args[1]); // args[0]는 FILE* 포인터
                checkFormatString("fprintf", formatString, args);
            }
        });
    }

    // snprintf 후킹
    if (libc_snprintf) {
        Interceptor.attach(libc_snprintf, {
            onEnter: function (args) {
                var formatString = Memory.readUtf8String(args[1]); // args[0]는 버퍼 포인터
                checkFormatString("snprintf", formatString, args);
            }
        });
    }
});
