"""KISA 소프트웨어 개발보안 가이드 49개 보안약점 진단 기준 카탈로그 (SFR-013/DAR-007/TST-006).

주의: 항목명·분류·번호는 공개된 KISA 시큐어코딩 가이드의 7대 분류 체계를 기준으로 구성한
근사 카탈로그이다. 실제 RFP 제출/평가 전에는 발주기관이 지정한 최신 공식 가이드 문서와
항목명·번호를 대조하여 확정해야 한다.

implementation_status: "IMPLEMENTED" (engine/rules/에 탐지 룰 존재) | "PLANNED" (카탈로그만 존재)
"""

STANDARD_ID = "KISA-SW-SEC-GUIDE"

_CATEGORY_INPUT = "입력데이터 검증 및 표현"
_CATEGORY_SECURITY_FEATURE = "보안기능"
_CATEGORY_TIME_STATE = "시간 및 상태"
_CATEGORY_ERROR = "에러처리"
_CATEGORY_CODE_ERROR = "코드오류"
_CATEGORY_ENCAPSULATION = "캡슐화"
_CATEGORY_API_MISUSE = "API 오용"

# (criteria_id, name, category, item_number, description, default_severity, implementation_status)
_RAW_ITEMS = [
    ("KISA-001", "SQL 삽입", _CATEGORY_INPUT, "1-1", "검증되지 않은 외부 입력값이 SQL 쿼리 문자열에 직접 결합되어 데이터베이스 조작이 가능한 취약점", "High", "IMPLEMENTED"),
    ("KISA-002", "경로 조작 및 자원 삽입", _CATEGORY_INPUT, "1-2", "검증되지 않은 외부 입력값이 파일/자원 경로에 사용되어 허용되지 않은 자원에 접근 가능한 취약점", "High", "IMPLEMENTED"),
    ("KISA-003", "크로스사이트 스크립트(XSS)", _CATEGORY_INPUT, "1-3", "검증되지 않은 외부 입력값이 응답 페이지에 그대로 포함되어 스크립트가 실행되는 취약점", "High", "IMPLEMENTED"),
    ("KISA-004", "운영체제 명령어 삽입", _CATEGORY_INPUT, "1-4", "검증되지 않은 외부 입력값이 운영체제 명령어 실행에 사용되는 취약점", "High", "IMPLEMENTED"),
    ("KISA-005", "위험한 형식 파일 업로드", _CATEGORY_INPUT, "1-5", "실행 가능한 스크립트 파일의 업로드를 제한하지 않아 서버 측 코드가 실행될 수 있는 취약점", "High", "IMPLEMENTED"),
    ("KISA-006", "신뢰되지 않는 URL 주소로의 자동접속 연결", _CATEGORY_INPUT, "1-6", "검증되지 않은 외부 입력값으로 리다이렉트되어 피싱 등에 악용될 수 있는 취약점(Open Redirect)", "Medium", "IMPLEMENTED"),
    ("KISA-007", "XQuery 삽입", _CATEGORY_INPUT, "1-7", "검증되지 않은 외부 입력값이 XQuery 쿼리에 삽입되는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-008", "XPath 삽입", _CATEGORY_INPUT, "1-8", "검증되지 않은 외부 입력값이 XPath 표현식에 삽입되는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-009", "LDAP 삽입", _CATEGORY_INPUT, "1-9", "검증되지 않은 외부 입력값이 LDAP 쿼리에 삽입되는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-010", "크로스사이트 요청 위조(CSRF)", _CATEGORY_INPUT, "1-10", "정상 사용자의 세션을 이용해 의도되지 않은 요청이 처리되는 취약점", "High", "IMPLEMENTED"),
    ("KISA-011", "서버사이드 요청 위조(SSRF)", _CATEGORY_INPUT, "1-11", "검증되지 않은 외부 입력값으로 서버가 임의 주소에 요청을 보내는 취약점", "High", "IMPLEMENTED"),
    ("KISA-012", "HTTP 응답분할", _CATEGORY_INPUT, "1-12", "검증되지 않은 외부 입력값이 HTTP 응답 헤더에 삽입되는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-013", "정수형 오버플로우", _CATEGORY_INPUT, "1-13", "정수 연산 결과가 자료형의 표현 범위를 초과하여 예기치 않은 동작을 유발하는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-014", "코드 삽입", _CATEGORY_INPUT, "1-14", "검증되지 않은 외부 입력값이 동적 코드 실행 함수(eval 등)에 전달되는 취약점", "High", "IMPLEMENTED"),
    ("KISA-015", "적절한 인증 없는 중요 기능 허용", _CATEGORY_SECURITY_FEATURE, "2-1", "인증 절차 없이 중요 기능(관리자 기능 등)에 접근할 수 있는 취약점", "High", "PLANNED"),
    ("KISA-016", "부적절한 인가", _CATEGORY_SECURITY_FEATURE, "2-2", "권한 검증 없이 타인의 자원 또는 관리 기능에 접근할 수 있는 취약점", "High", "PLANNED"),
    ("KISA-017", "중요한 자원에 대한 잘못된 권한 설정", _CATEGORY_SECURITY_FEATURE, "2-3", "중요 자원(파일, DB 등)에 과도하게 허용적인 접근 권한이 설정된 취약점", "Medium", "PLANNED"),
    ("KISA-018", "취약한 암호화 알고리즘 사용", _CATEGORY_SECURITY_FEATURE, "2-4", "안전성이 검증되지 않았거나 취약한 것으로 알려진 암호화/해시 알고리즘(MD5, SHA1, DES 등)을 사용하는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-019", "암호화되지 않은 중요정보", _CATEGORY_SECURITY_FEATURE, "2-5", "개인정보 등 중요정보를 암호화하지 않고 저장·전송하는 취약점", "High", "PLANNED"),
    ("KISA-020", "하드코드된 비밀번호", _CATEGORY_SECURITY_FEATURE, "2-6", "비밀번호, 계정 정보 등이 소스코드에 평문으로 고정되어 있는 취약점", "High", "IMPLEMENTED"),
    ("KISA-021", "적절하지 않은 난수 값 사용", _CATEGORY_SECURITY_FEATURE, "2-7", "보안 목적(토큰, 세션ID 등)에 암호학적으로 안전하지 않은 난수 생성기를 사용하는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-022", "하드코드된 암호화 키", _CATEGORY_SECURITY_FEATURE, "2-8", "암호화 키, salt, IV 등이 소스코드에 고정되어 있는 취약점", "High", "IMPLEMENTED"),
    ("KISA-023", "취약한 비밀번호 허용", _CATEGORY_SECURITY_FEATURE, "2-9", "비밀번호 복잡도/길이 등 정책을 강제하지 않는 취약점", "Medium", "PLANNED"),
    ("KISA-024", "사용자 하드디스크에 저장되는 쿠키를 통한 정보노출", _CATEGORY_SECURITY_FEATURE, "2-10", "중요정보를 영구 쿠키 등 클라이언트 저장소에 평문 저장하는 취약점", "Medium", "PLANNED"),
    ("KISA-025", "주석문 안에 포함된 시스템 주요정보", _CATEGORY_SECURITY_FEATURE, "2-11", "소스코드 주석에 계정, 내부 경로 등 민감정보가 노출되는 취약점", "Low", "PLANNED"),
    ("KISA-026", "솔트 없이 일방향 해시함수 사용", _CATEGORY_SECURITY_FEATURE, "2-12", "비밀번호 해시 시 salt를 사용하지 않아 레인보우 테이블 공격에 취약한 문제", "Medium", "PLANNED"),
    ("KISA-027", "경쟁조건: 검사 시점과 사용 시점(TOCTOU)", _CATEGORY_TIME_STATE, "3-1", "자원 상태를 검사한 시점과 실제 사용하는 시점 사이의 경쟁조건을 이용한 취약점", "Medium", "PLANNED"),
    ("KISA-028", "종료되지 않는 반복문 또는 재귀함수", _CATEGORY_TIME_STATE, "3-2", "종료 조건이 보장되지 않아 자원 고갈을 유발할 수 있는 반복/재귀 구조", "Low", "PLANNED"),
    ("KISA-029", "오류 메시지를 통한 정보노출", _CATEGORY_ERROR, "4-1", "예외 발생 시 스택 트레이스 등 시스템 내부 정보가 사용자에게 노출되는 취약점", "Medium", "PLANNED"),
    ("KISA-030", "오류 상황 대응 부재", _CATEGORY_ERROR, "4-2", "예외적인 상황(널값, 자원 부족 등)에 대한 처리가 누락된 취약점", "Medium", "PLANNED"),
    ("KISA-031", "부적절한 예외처리", _CATEGORY_ERROR, "4-3", "여러 예외를 하나로 뭉뚱그려 처리하거나 예외 유형을 지나치게 광범위하게 처리하는 문제", "Low", "PLANNED"),
    ("KISA-032", "빈 Catch 블록", _CATEGORY_ERROR, "4-4", "예외를 포착하고도 아무 처리 없이 무시하여 오류 상황이 은폐되는 취약점", "Low", "IMPLEMENTED"),
    ("KISA-033", "널 포인터 역참조", _CATEGORY_CODE_ERROR, "5-1", "널 값 가능성이 있는 참조를 검증 없이 역참조하여 예외가 발생하는 결함", "Medium", "PLANNED"),
    ("KISA-034", "부적절한 자원 해제", _CATEGORY_CODE_ERROR, "5-2", "파일 핸들, 커넥션 등 자원을 명시적으로 해제하지 않아 고갈을 유발하는 결함", "Medium", "PLANNED"),
    ("KISA-035", "해제된 자원 사용", _CATEGORY_CODE_ERROR, "5-3", "이미 해제된 자원을 재사용하는 결함(Use-After-Free 계열)", "Medium", "PLANNED"),
    ("KISA-036", "초기화되지 않은 변수 사용", _CATEGORY_CODE_ERROR, "5-4", "초기화 없이 변수를 사용하여 예측할 수 없는 동작을 유발하는 결함", "Low", "PLANNED"),
    ("KISA-037", "신뢰할 수 없는 데이터의 역직렬화", _CATEGORY_CODE_ERROR, "5-5", "검증되지 않은 외부 데이터를 역직렬화하여 임의 코드 실행으로 이어질 수 있는 취약점", "High", "IMPLEMENTED"),
    ("KISA-038", "정수형 변환 오류", _CATEGORY_CODE_ERROR, "5-6", "자료형 변환 과정에서 값 손실 또는 부호 오류가 발생하는 결함", "Low", "PLANNED"),
    ("KISA-039", "동일한 상수 사용에 의한 잘못된 값 참조", _CATEGORY_CODE_ERROR, "5-7", "매직 넘버/상수 재사용으로 의도치 않은 값이 참조되는 결함", "Low", "PLANNED"),
    ("KISA-040", "할당 후 미검사 반환값", _CATEGORY_CODE_ERROR, "5-8", "함수 반환값(오류 코드 등)을 검사하지 않고 사용하는 결함", "Low", "PLANNED"),
    ("KISA-041", "잘못된 세션에 의한 데이터 정보노출", _CATEGORY_ENCAPSULATION, "6-1", "세션 관리 오류로 인해 다른 사용자의 세션 데이터가 노출되는 취약점", "High", "PLANNED"),
    ("KISA-042", "제거되지 않고 남은 디버그 코드", _CATEGORY_ENCAPSULATION, "6-2", "운영 환경에 디버그/테스트 목적의 코드나 설정이 그대로 남아있는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-043", "시스템 데이터 정보노출", _CATEGORY_ENCAPSULATION, "6-3", "내부 시스템 구조/설정 정보가 외부에 노출되는 취약점", "Medium", "PLANNED"),
    ("KISA-044", "Public 메소드로부터 반환된 Private 배열", _CATEGORY_ENCAPSULATION, "6-4", "내부 배열을 참조로 반환하여 외부에서 내부 상태를 임의 변경할 수 있는 캡슐화 결함", "Low", "PLANNED"),
    ("KISA-045", "Private 배열에 Public 데이터 할당", _CATEGORY_ENCAPSULATION, "6-5", "외부에서 전달받은 배열 참조를 그대로 내부 상태에 저장하는 캡슐화 결함", "Low", "PLANNED"),
    ("KISA-046", "잘못된 파일 업로드 권한 부여(파일 권한 설정 오류)", _CATEGORY_ENCAPSULATION, "6-6", "파일/디렉터리에 과도하게 허용적인 권한(예: 0777)을 부여하는 취약점", "Medium", "IMPLEMENTED"),
    ("KISA-047", "DNS Lookup에 의존한 보안 결정", _CATEGORY_API_MISUSE, "7-1", "DNS 조회 결과(호스트명 등)를 신뢰하여 보안 결정을 내리는 취약점", "Low", "PLANNED"),
    ("KISA-048", "취약한 API 사용", _CATEGORY_API_MISUSE, "7-2", "안전하지 않거나 지원 종료된 API를 사용하는 취약점", "Low", "PLANNED"),
    ("KISA-049", "운영체제 명령 실행 API 오용", _CATEGORY_API_MISUSE, "7-3", "운영체제 명령 실행 API를 목적에 맞지 않게 오용하는 취약점", "Medium", "PLANNED"),
]

assert len(_RAW_ITEMS) == 49, f"KISA 카탈로그는 49개 항목이어야 합니다 (현재 {len(_RAW_ITEMS)}개)"


def catalog_rows() -> list[dict]:
    return [
        {
            "criteria_id": criteria_id,
            "name": name,
            "description": description,
            "standard_id": STANDARD_ID,
            "category": category,
            "item_number": item_number,
            "reference_info": "KISA 소프트웨어 개발보안 가이드",
            "is_active": True,
            "default_severity": severity,
            "implementation_status": implementation_status,
        }
        for criteria_id, name, category, item_number, description, severity, implementation_status in _RAW_ITEMS
    ]
