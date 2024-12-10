WEB-SER-	MOB-SER-	HTS-SER-	052	기술적 보안	5. 운영 관리	5.8 공개서버 보안	5.8.4 (일반공통) 서비스 보호	서버 사이드 템플릿 인젝션(SSTI)	5	"o 서버 사이트 템플릿 인젝션(SSTI)는 웹 서버의 템플릿 엔진이 입력값을 적절하게 처리하지 않아 공격자가 서버 측의 템플릿을 조작할 수 있는 공격 기법으로, 템플릿 엔진에 임의 코드 주입을 통한 원격 코드 실행 등의 위협이 발생될 수 있으므로, 사용자 입력값이 서버측 템플릿 코드에 의해 실행 가능 한지를 점검
* (평가 예시)
 - https://[target]/url?payload=fs${34*95}ec
 - https://[target]/url?payload={class.getResource(""../../../../../index.htm"").getContent()}
 - https://[target]/url?payload={T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"	o										

 