Java.perform(function () {
  console.log("[*] 악성파일 업로드 및 실행 가능 여부 점검 시작...");

  // ======================
  // 1. 파일 업로드 클래스 및 메서드 후킹
  // ======================
  const FileInputStream = Java.use("java.io.FileInputStream");
  const FileOutputStream = Java.use("java.io.FileOutputStream");
  const File = Java.use("java.io.File");

  FileInputStream.$init.overload("java.lang.String").implementation = function (path) {
      console.log(`[+] 파일 업로드 감지 - 경로: ${path}`);

      // 업로드 파일 확장자 확인
      const extension = path.substring(path.lastIndexOf(".") + 1).toLowerCase();
      console.log(`[+] 업로드된 파일 확장자: ${extension}`);

      // 악성파일 여부 판단
      if (["jsp", "asp", "php", "exe", "sh"].includes(extension)) {
          console.log(`[!] 경고: 악성파일 업로드 시도 감지 - ${path}`);
          alertUser(`악성파일(${extension}) 업로드 시도 감지됨: ${path}`);
      }

      return this.$init(path);
  };

  // ======================
  // 2. 업로드된 파일 실행 가능 여부 점검
  // ======================
  FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
      const path = file.getAbsolutePath();
      console.log(`[+] 업로드된 파일 경로: ${path}`);

      // 업로드된 파일의 실행 가능 여부 점검
      if (["jsp", "asp", "php", "exe", "sh"].includes(path.substring(path.lastIndexOf(".") + 1).toLowerCase())) {
          console.log(`[!] 경고: 악성파일 실행 가능 여부 점검 필요 - ${path}`);
          alertUser(`업로드된 악성파일 실행 가능 여부 확인 필요: ${path}`);
      }

      return this.$init(file, append);
  };

  // ======================
  // 3. 실시간 알림 함수
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

  console.log("[*] 악성파일 업로드 및 실행 가능 여부 점검 완료.");
});
