# 연구 목적

Docker Official Image에서 Syft로 SBOM을 생성하고,
SBOM에 포함된 CPE를 재현 가능하게 분석하는 파일럿 실험이다.

# 개발 호스트

- Pilot 관련 개발, 테스트, 파일 검토는 macOS arm64 또는
  WSL2/Linux x86_64 호스트에서 수행할 수 있다.
- 운영체제별 가상환경과 의존성은 각 호스트에서 새로 생성하고 설치한다.
- WSL에서 생성한 `.venv`를 macOS에서 재사용하지 않는다.
- macOS에서 생성한 `.venv`를 WSL에서 재사용하지 않는다.
- macOS에서는 Docker Desktop을 사용할 수 있다.

# 분석 대상 플랫폼

- 개발 호스트의 운영체제와 CPU 아키텍처에 관계없이 모든 Pilot Docker
  이미지 분석 대상은 항상 `linux/amd64`로 유지한다.
- Mac mini의 호스트 아키텍처가 arm64라는 이유로 Pilot 플랫폼을
  `linux/arm64`로 변경하지 않는다.
- Docker 이미지 pull, inspect, manifest 선택, SBOM 생성 등 플랫폼의
  영향을 받는 모든 명령에서 기존 `linux/amd64` 통제 조건을 유지한다.
- `images.yaml`의 이미지, 태그, 플랫폼 및 digest 정책은 연구 재현성
  조건이므로 변경하지 않는다.
- macOS에서 `linux/amd64` 이미지를 실행할 때 Docker의 아키텍처
  에뮬레이션이 사용될 수 있다. 에뮬레이션으로 실행 속도가 느려져도
  분석 대상 플랫폼을 변경하지 않는다.

# 재현성 규칙

- 기존 WSL2 실험과 Mac 실험은 동일한 이미지 reference, tag, platform,
  manifest digest를 사용한다.
- 호스트 환경 차이로 생성 결과가 달라질 가능성이 있으면 기존 결과를
  자동으로 덮어쓰지 않고 먼저 차이를 비교하여 보고한다.
- 저장된 Pilot 산출물은 연구 데이터이므로 명시적인 요청 없이
  재생성하거나 수정하지 않는다.
- 원본 출력, 실행 환경, 오류 및 실패 사례를 보존한다.
- 실패하거나 결과가 없는 표본을 임의로 제외하지 않는다.
- 기존 실험 결과와 사용자의 변경사항을 임의로 덮어쓰거나 되돌리지 않는다.

# Python 실행 환경

- Python 테스트는 호스트별로 새로 만든 Pilot 전용 가상환경에서 실행한다.
- 프로젝트 루트에서 다음 구조와 명령을 사용한다.

```bash
python -m venv pilot/.venv
source pilot/.venv/bin/activate
python -m pip install -r pilot/requirements.txt
cd pilot
.venv/bin/python -m unittest discover -s tests -v
```

# 작업 규칙

- 요청받은 작업 범위만 수행하고 다음 실험 단계로 임의 확장하지 않는다.
- 작업 후 변경 파일, 실행 명령, 검증 결과와 실패 사항을 보고한다.
- 명시적 요청 없이 Git 커밋이나 푸시를 수행하지 않는다.

# Syft SBOM 생성 규칙

- SBOM 생성 도구는 Syft `1.49.0`으로 고정한다.
- `results/image-digests.json`의 `pinned_reference`를 입력으로 사용한다.
- 분석 플랫폼은 `linux/amd64`, 이미지 소스는 원격 registry로 고정한다.
- 출력 형식은 CycloneDX JSON, 분석 범위는 `squashed`로 고정한다.
- 온라인 enrichment를 사용하지 않는다.
- SBOM 결과는 `results/sboms/`에 저장한다.
- 명시적인 덮어쓰기 옵션 없이 기존 SBOM을 덮어쓰지 않는다.
- CPE가 없다는 이유로 표본이나 SBOM을 제외하지 않는다.
- 명시적 요청 없이 실제 전체 SBOM 생성이나 취약점 분석 단계로 확장하지 않는다.
