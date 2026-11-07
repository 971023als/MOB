Java.perform(function () {
    // 대상 함수 후킹 설정
    var libc_printf = Module.findExportByName(null, 'printf');      // printf
    var libc_sprintf = Module.findExportByName(null, 'sprintf');    // sprintf
    var libc_fprintf = Module.findExportByName(null, 'fprintf');    // fprintf
    var libc_snprintf = Module.findExportByName(null, 'snprintf');  // snprintf

    // 사용자 입력에 특정 키워드나 값을 검사하기 위한 조건
    var suspiciousKeywords = ["password", "creditcard", "secret"]; // 민감 데이터 예시

    // 공통 로직: 포맷 문자열 점검 및 사용자 입력 분석
    function checkFormatString(functionName, formatString, args, varargsStart) {
        console.log(`[*] ${functionName} 호출 감지`);
        console.log(`    포맷 문자열: ${formatString}`);

        // 포맷 문자열에 위험 요소 탐지
        if (formatString.includes('%s') || formatString.includes('%x') || formatString.includes('%n')) {
            console.warn(`[!] ${functionName}에서 포맷 문자열 취약점 발견!`);
        }

        // 사용자 입력에 의심스러운 키워드 포함 여부 탐지
        // 첫 번째 가변 인자 위치는 함수별로 다르므로 varargsStart로 받는다.
        for (var i = varargsStart; i < args.length; i++) {
            var argValue = null;
            try {
                argValue = Memory.readUtf8String(args[i]); // 숫자 인자 등 문자열이 아닌 값은 건너뜀
            } catch (e) {
                continue;
            }
            if (argValue) {
                suspiciousKeywords.forEach(function (keyword) {
                    if (argValue.includes(keyword)) {
                        console.error(`[!] ${functionName}: 민감 키워드(${keyword})가 포함된 입력 탐지!`);
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
                checkFormatString("printf", formatString, args, 1);
            }
        });
    }

    // sprintf 후킹
    if (libc_sprintf) {
        Interceptor.attach(libc_sprintf, {
            onEnter: function (args) {
                // sprintf(buf, format, ...): args[0]은 버퍼, 포맷은 args[1]
                var formatString = Memory.readUtf8String(args[1]);
                checkFormatString("sprintf", formatString, args, 2);
            }
        });
    }

    // fprintf 후킹
    if (libc_fprintf) {
        Interceptor.attach(libc_fprintf, {
            onEnter: function (args) {
                var formatString = Memory.readUtf8String(args[1]); // args[0]는 FILE* 포인터
                checkFormatString("fprintf", formatString, args, 2);
            }
        });
    }

    // snprintf 후킹
    if (libc_snprintf) {
        Interceptor.attach(libc_snprintf, {
            onEnter: function (args) {
                // snprintf(buf, size, format, ...): 포맷은 args[2]
                var formatString = Memory.readUtf8String(args[2]);
                checkFormatString("snprintf", formatString, args, 3);
            }
        });
    }
});
