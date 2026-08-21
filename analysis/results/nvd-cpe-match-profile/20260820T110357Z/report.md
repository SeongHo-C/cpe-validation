# NVD CPE Match Criteria 사용 형태 전수 분석 — 20260820T110357Z

생성 시각(UTC): `2026-08-21T00:50:30.801290+00:00`

> 이 보고서는 raw `criteria` 문자열을 고유 CPE로 간주하지 않는다. CPE Dictionary 비교, version 의미 해석, applicability 판정은 수행하지 않았다.

## A. Dataset

- Snapshot ID/status: `20260820T110357Z` / `COMPLETE`
- CVE records: 380,865
- Configurations: 760,120
- Nodes: 1,204,210
- CPE Match occurrences: 3,170,148
- Manifest SHA-256: `80b6107f5225923794d725b252527f575ad2b0c800765fc5ce6d0b07c18d94eb`
- Content SHA-256: `a8a1b6ca66a0383272a3ca035559229b1fc59535f029828b984a3998234c6eab`

저장 구조는 `NvdCpeMatch`가 CVE record를 FK로 참조하고, configuration/node/match index로 위치를 보존하는 flattened row이다. operator/negate는 configuration과 node에서 각 occurrence로 복사된다. range key가 없으면 NULL이며, 키가 있으면 빈 문자열도 그대로 저장된다. 전체 필드 타입과 nullability는 `summary.json`의 `storage_structure`에 있다.

## B. Criteria Cardinality

- Total occurrences: 3,170,148
- Distinct criteria strings: 428,417
- Distinct matchCriteriaIds: 549,393
- vulnerable=true: 2,567,417
- vulnerable=false: 602,731
- vulnerable=NULL/비정상: 0
- 한 번만 등장한 criteria: 215,050
- 2회 이상 등장한 criteria: 213,367
- criteria 최대 occurrence: 51,458

### Occurrence 상위 criteria strings

| criteria | occurrences | CVEs | matchCriteriaIds | range tuples |
| ---: | ---: | ---: | ---: | ---: |
| cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:* | 51,458 | 14,306 | 13,497 | 13,497 |
| cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:* | 10,249 | 8,635 | 1 | 1 |
| cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:* | 6,037 | 5,810 | 564 | 564 |
| cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* | 4,836 | 2,938 | 292 | 292 |
| cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:* | 4,608 | 4,245 | 304 | 304 |
| cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:* | 4,555 | 4,359 | 1 | 1 |
| cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:* | 4,363 | 4,137 | 1 | 1 |
| cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:* | 4,339 | 3,767 | 1 | 1 |
| cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:* | 4,259 | 3,746 | 1 | 1 |
| cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:* | 4,145 | 3,315 | 225 | 225 |
| cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:* | 4,020 | 4,003 | 1 | 1 |
| cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:* | 3,495 | 3,489 | 1 | 1 |
| cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:* | 3,444 | 3,434 | 1 | 1 |
| cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:* | 3,282 | 1,327 | 1,384 | 1,384 |
| cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:* | 3,253 | 3,123 | 1 | 1 |
| cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:* | 3,168 | 3,051 | 1 | 1 |
| cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:* | 2,833 | 2,660 | 1 | 1 |
| cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:* | 2,803 | 2,312 | 392 | 392 |
| cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:* | 2,793 | 1,116 | 1,188 | 1,188 |
| cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:* | 2,724 | 2,593 | 1 | 1 |

동일 criteria가 여러 matchCriteriaId에 연결된 criteria 수는 21,115, 반대 방향(동일 ID→여러 criteria)의 ID 수는 0이다. 양방향의 전체 multiplicity/occurrence 분포와 대표 매핑은 `summary.json`에 있다.

## C. CPE Field Profile

### part 분포

| part | occurrences | distinct criteria |
| ---: | ---: | ---: |
| a | 1,347,393 | 266,808 |
| o | 1,231,685 | 92,945 |
| h | 591,070 | 68,664 |
| other_or_malformed | 0 | 0 |

### version field 분포

| version 형태 | occurrences | distinct criteria |
| ---: | ---: | ---: |
| star | 539,827 | 72,080 |
| concrete | 1,725,187 | 271,514 |
| hyphen | 905,134 | 84,823 |
| other | 0 | 0 |

11개 모든 CPE field의 `*`/`-`/concrete/empty 분포는 `summary.json`의 `all_field_token_distribution`에 occurrence와 distinct criteria 기준으로 각각 기록했다.

### 모든 CPE field의 raw token 형태 (occurrence 기준)

| field | `*` | `-` | concrete | empty |
| ---: | ---: | ---: | ---: | ---: |
| part | 0 | 0 | 3,170,148 | 0 |
| vendor | 1 | 11 | 3,170,136 | 0 |
| product | 2 | 11 | 3,170,135 | 0 |
| version | 539,827 | 905,134 | 1,725,187 | 0 |
| update | 2,657,681 | 36,098 | 476,369 | 0 |
| edition | 3,119,114 | 685 | 50,349 | 0 |
| language | 3,169,812 | 11 | 325 | 0 |
| sw_edition | 3,098,585 | 6,588 | 64,975 | 0 |
| target_sw | 3,107,080 | 2,675 | 60,393 | 0 |
| target_hw | 3,124,317 | 653 | 45,178 | 0 |
| other | 3,169,842 | 0 | 306 | 0 |

## D. Version Range Profile

- Range 없음: 2,671,494
- Range 있음: 498,654 (15.72967571%)

### 실제 존재하는 range-field 조합

| present fields | occurrences | distinct criteria |
| ---: | ---: | ---: |
| none | 2,671,494 | 367,280 |
| version_end_excluding | 223,937 | 34,855 |
| version_end_including | 90,178 | 28,975 |
| version_start_excluding | 10 | 9 |
| version_start_excluding + version_end_excluding | 471 | 148 |
| version_start_excluding + version_end_including | 139 | 74 |
| version_start_including | 1,320 | 334 |
| version_start_including + version_end_excluding | 137,178 | 6,455 |
| version_start_including + version_end_including | 45,421 | 4,436 |

빈 boundary 문자열 occurrence의 대표 사례(최대 20개)는 `summary.json`의 `empty_boundary_string_examples`에 있다.

### Boundary field별 NULL/present/empty

| field | NULL | present | empty string | non-empty |
| ---: | ---: | ---: | ---: | ---: |
| version_start_including | 2,986,229 | 183,919 | 2 | 183,917 |
| version_start_excluding | 3,169,528 | 620 | 0 | 620 |
| version_end_including | 3,034,410 | 135,738 | 0 | 135,738 |
| version_end_excluding | 2,808,562 | 361,586 | 0 | 361,586 |

## E. Version × Range Cross Analysis

### Occurrence 기준

| Criteria version 형태 | Range 없음 | Range 있음 |
| --- | ---: | ---: |
| `*` | 41,173 | 498,654 |
| concrete | 1,725,187 | 0 |
| `-` | 905,134 | 0 |
| 기타/empty/malformed | 0 | 0 |

### Distinct criteria string 기준(셀별)

| Criteria version 형태 | Range 없음 | Range 있음 |
| --- | ---: | ---: |
| `*` | 10,943 | 62,808 |
| concrete | 271,514 | 0 |
| `-` | 84,823 | 0 |
| 기타/empty/malformed | 0 | 0 |

Concrete version+range와 `-`+range의 최대 20개 대표 occurrence는 CVE ID, criteria, vulnerable, 네 boundary, matchCriteriaId와 함께 `summary.json`에 수록했다(0건인 유형의 배열은 비어 있다).
동일 criteria가 range 없음과 있음 양쪽에서 사용된 경우는 1,671개다.

## F. Criteria × Range Multiplicity

- Range tuple 1종류인 criteria: 407,302
- Range tuple 2종류 이상인 criteria: 21,115
- 한 criteria의 최대 range tuple 종류: 13,497

### Range variant가 많은 criteria 상위 20개

| criteria | occurrences | CVEs | range tuples |
| ---: | ---: | ---: | ---: |
| cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:* | 51,458 | 14,306 | 13,497 |
| cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:* | 3,282 | 1,327 | 1,384 |
| cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:* | 2,793 | 1,116 | 1,188 |
| cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:* | 6,037 | 5,810 | 564 |
| cpe:2.3:a:php:php:*:*:*:*:*:*:*:* | 951 | 513 | 421 |
| cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:* | 2,803 | 2,312 | 392 |
| cpe:2.3:a:mattermost:mattermost_server:*:*:*:*:*:*:*:* | 1,168 | 467 | 347 |
| cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:* | 1,789 | 515 | 346 |
| cpe:2.3:a:f5:big-ip_application_security_manager:*:*:*:*:*:*:*:* | 1,623 | 478 | 336 |
| cpe:2.3:a:mozilla:thunderbird:*:*:*:*:*:*:*:* | 1,593 | 1,420 | 330 |
| cpe:2.3:a:f5:big-ip_local_traffic_manager:*:*:*:*:*:*:*:* | 1,527 | 444 | 326 |
| cpe:2.3:a:xwiki:xwiki:*:*:*:*:*:*:*:* | 520 | 243 | 325 |
| cpe:2.3:a:f5:big-ip_advanced_firewall_manager:*:*:*:*:*:*:*:* | 1,548 | 454 | 320 |
| cpe:2.3:a:f5:big-ip_link_controller:*:*:*:*:*:*:*:* | 1,478 | 432 | 318 |
| cpe:2.3:a:f5:big-ip_policy_enforcement_manager:*:*:*:*:*:*:*:* | 1,495 | 436 | 312 |
| cpe:2.3:a:f5:big-ip_analytics:*:*:*:*:*:*:*:* | 1,448 | 422 | 312 |
| cpe:2.3:a:f5:big-ip_application_acceleration_manager:*:*:*:*:*:*:*:* | 1,474 | 431 | 308 |
| cpe:2.3:a:f5:big-ip_global_traffic_manager:*:*:*:*:*:*:*:* | 1,417 | 410 | 305 |
| cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:* | 4,608 | 4,245 | 304 |
| cpe:2.3:a:f5:big-ip_domain_name_system:*:*:*:*:*:*:*:* | 1,438 | 404 | 302 |

각 상위 사례의 대표 range tuple 최대 20개와 tuple별 occurrence/CVE 수는 `summary.json`에 있다.

## G. Vulnerable Usage

| group | distinct criteria | occurrences | distinct CVEs |
| ---: | ---: | ---: | ---: |
| true_only | 363,408 | 2,121,611 | 275,941 |
| false_only | 56,027 | 348,032 | 28,953 |
| both | 8,982 | 700,505 | 91,623 |
| null_or_unexpected | 0 | 0 | 0 |

True/false 양쪽에서 사용된 상위 20개 criteria와 각 boolean별 occurrence/CVE breakdown은 `summary.json`에 있다.

## H. Configuration Structure

원본 JSON 전체에서 configuration 760,120개, node 1,204,210개를 집계했다. operator/negate의 entity 분포와 cpeMatch occurrence 기준 configuration/node operator × vulnerable, AND/OR, effective negate 교차분포는 `summary.json`에 있다. 복잡한 구조를 취약 여부로 판정하지 않았다.

### Node operator (전체 node entity 기준)

| operator | nodes | distinct CVEs |
| ---: | ---: | ---: |
| AND | 119 | 23 |
| OR | 1,204,091 | 311,352 |

### Configuration operator (전체 configuration entity 기준)

| operator | configurations | distinct CVEs |
| ---: | ---: | ---: |
| AND | 444,047 | 48,083 |
| <NULL> | 316,073 | 267,197 |

### Configuration negate (전체 configuration entity 기준)

| negate | configurations | distinct CVEs |
| ---: | ---: | ---: |
| <NULL> | 760,120 | 311,367 |

### Node negate (전체 node entity 기준)

| negate | nodes | distinct CVEs |
| ---: | ---: | ---: |
| false | 1,204,210 | 311,367 |

### cpeMatch occurrence × node AND/OR × vulnerable

| node operator | vulnerable=false | vulnerable=true | total |
| --- | ---: | ---: | ---: |
| AND | 24 | 233 | 257 |
| OR | 602,707 | 2,567,184 | 3,169,891 |

### cpeMatch occurrence × configuration operator × vulnerable

| configuration operator | vulnerable=false | vulnerable=true | total |
| --- | ---: | ---: | ---: |
| <NULL> | 2,524 | 1,933,408 | 1,935,932 |
| AND | 600,207 | 634,009 | 1,234,216 |

### cpeMatch occurrence × configuration/node negate × vulnerable

| negate 포함 | vulnerable=false | vulnerable=true | total |
| --- | ---: | ---: | ---: |
| false | 602,731 | 2,567,417 | 3,170,148 |

## I. Exceptional Cases

### Structural parser status

| status | occurrences | occurrence % | distinct criteria | distinct % |
| ---: | ---: | ---: | ---: | ---: |
| STRUCTURALLY_VALID | 3,170,148 | 100.0 | 428,417 | 100.0 |
| INVALID_PREFIX | 0 | 0.0 | 0 | 0.0 |
| INVALID_FIELD_COUNT | 0 | 0.0 | 0 | 0.0 |
| INVALID_ESCAPE | 0 | 0.0 | 0 | 0.0 |
| INVALID_PART | 0 | 0.0 | 0 | 0.0 |

### Parser-attention categories

| category | occurrences | occurrence % | distinct criteria | distinct % |
| ---: | ---: | ---: | ---: | ---: |
| structural_invalid | 0 | 0.0 | 0 | 0.0 |
| empty_vendor | 0 | 0.0 | 0 | 0.0 |
| empty_product | 0 | 0.0 | 0 | 0.0 |
| empty_version | 0 | 0.0 | 0 | 0.0 |
| contains_escape_sequence | 113,161 | 3.56958098 | 23,387 | 5.4589337 |
| embedded_unescaped_wildcard | 21 | 0.00066243 | 11 | 0.00256759 |

빈 vendor/product/version, escape sequence, embedded unescaped wildcard는 서로 겹칠 수 있는 parser-attention 유형으로 별도 집계했다. `*`와 `-`는 사용 위치를 보고할 뿐 자동 오류로 분류하지 않았다. 유형별 비율과 대표 최대 30개 criteria는 `summary.json`에 있다.

## J. Interpretation (다음 단계의 판단 근거)

1. `criteria`는 raw 문자열의 반복 사용을 세는 안정적인 관측 단위이지만, 21,115개 문자열이 여러 range tuple과 연결되어 있으므로 그 자체가 완전한 applicability condition인지 여부는 분리해 검토해야 한다.
2. Range field는 전체 occurrence의 15.72967571%에서 사용된다. 빈도뿐 아니라 동일 criteria의 range multiplicity와 range 있음/없음 양쪽 사용을 함께 보아야 한다.
3. Concrete version+range는 0건, `-`+range는 0건 관측되었다. 0이 아닌 유형은 별도 예외 경로가 필요하다.
4. True/false 양쪽에 걸친 criteria는 8,982개다. 따라서 vulnerable은 raw criteria identity와 독립된 occurrence/context 속성으로 보존하는 방안을 다음 단계에서 검토할 근거가 있다.
5. 추천안(정의 확정 아님): 다음 단계의 후보 키를 최소한 `criteria`, 4-field range tuple, vulnerable, configuration/node context로 분해해 비교하고, matchCriteriaId의 양방향 다중 연결도 별도 식별자 특성으로 검증한다. 이번 결과로 deduplication artifact나 unique CPE catalog는 만들지 않았다.

## Safety

- 모든 DB 집계 트랜잭션 READ ONLY: `true`
- 작업 전후 전체 DB table row count 및 NVD/CPE snapshot metadata 동일: `true`
- 내부 aggregate 합계 불변식 검증 통과: `true`
- CPE Dictionary membership/exact/family/deprecated 비교 query: 0건
- Firmware/SBOM/Ground Truth 변경 query: 0건
- 전체 작업 전후 table별 count는 `summary.json`의 `safety`에 기록했다.
