# NVD Configuration Criteria × CPE Dictionary Coverage

생성 시각(UTC): `2026-08-21T10:48:54.392110+00:00`

> 이 보고서의 단위는 distinct Configuration criteria expression이다. 이를 unique CPE로 해석하지 않으며, raw exact string과 raw part/vendor/product tuple coverage만 관측한다.

## A. Dataset

- NVD Snapshot: `20260820T110357Z` (`COMPLETE`)
- CPE Dictionary Snapshot: `20260819T035002Z` (`COMPLETE`)
- CVE records: 380,865
- CVEs with cpeMatch: 311,367
- CPE Match occurrences: 3,170,148
- Distinct Configuration criteria expressions: 428,417
- Dictionary CPE Names: 1,811,261
- Dictionary product tuples: 152,784

## B. Overall Coverage

| Coverage class | Distinct criteria | % | Occurrences | % | Distinct CVEs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Exact present | 269,267 | 62.85161420 | 2,413,552 | 76.13373256 | 166,958 |
| Exact absent + same product tuple | 83,194 | 19.41893062 | 599,022 | 18.89571086 | 181,413 |
| Configuration-only product tuple | 75,956 | 17.72945518 | 157,574 | 4.97055658 | 42,516 |

Exact-absent expression 159,150개 중 동일 product tuple이 존재하는 비율은 52.27395539%다. Distinct-CVE 열은 class 간 중복될 수 있으므로 합산하지 않는다.

## C. Criteria Form × Coverage

| Group | Criteria | Occurrences | CVEs | Exact criteria/occ. | Same tuple criteria/occ. | Configuration-only criteria/occ. |
| --- | ---: | ---: | ---: | --- | --- | --- |
| CONCRETE | 271,514 | 1,725,187 | 168,050 | 188,151 (69.2970%) / 1,518,410 (88.0142%) | 27,657 (10.1862%) / 89,915 (5.2119%) | 55,706 (20.5168%) / 116,862 (6.7739%) |
| WILDCARD_NO_RANGE | 9,272 | 30,183 | 9,930 | 0 (0.0000%) / 0 (0.0000%) | 5,584 (60.2243%) / 24,983 (82.7718%) | 3,688 (39.7757%) / 5,200 (17.2282%) |
| WILDCARD_RANGE | 61,137 | 352,351 | 135,967 | 0 (0.0000%) / 0 (0.0000%) | 48,208 (78.8524%) / 327,399 (92.9184%) | 12,929 (21.1476%) / 24,952 (7.0816%) |
| WILDCARD_BOTH | 1,671 | 157,293 | 53,707 | 0 (0.0000%) / 0 (0.0000%) | 1,421 (85.0389%) / 155,913 (99.1227%) | 250 (14.9611%) / 1,380 (0.8773%) |
| HYPHEN | 84,823 | 905,134 | 55,910 | 81,116 (95.6297%) / 895,142 (98.8961%) | 324 (0.3820%) / 812 (0.0897%) | 3,383 (3.9883%) / 9,180 (1.0142%) |
| OTHER | 0 | 0 | 0 | 0 (0.0000%) / 0 (0.0000%) | 0 (0.0000%) / 0 (0.0000%) | 0 (0.0000%) / 0 (0.0000%) |

각 form의 class별 occurrence, distinct-CVE, exact-absent rollup 및 비율은 `summary.json`에 수록했다.

### Concrete/Hyphen + range 예외 확인

- CONCRETE_WITH_RANGE: 0 expressions, 0 occurrences
- HYPHEN_WITH_RANGE: 0 expressions, 0 occurrences

## D. Vulnerable Usage × Coverage

| Group | Criteria | Occurrences | CVEs | Exact criteria/occ. | Same tuple criteria/occ. | Configuration-only criteria/occ. |
| --- | ---: | ---: | ---: | --- | --- | --- |
| TRUE_ONLY | 363,408 | 2,121,611 | 275,941 | 211,168 (58.1077%) / 1,546,009 (72.8696%) | 79,816 (21.9632%) / 431,256 (20.3268%) | 72,424 (19.9291%) / 144,346 (6.8036%) |
| FALSE_ONLY | 56,027 | 348,032 | 28,953 | 51,005 (91.0365%) / 335,368 (96.3613%) | 2,232 (3.9838%) / 4,636 (1.3321%) | 2,790 (4.9797%) / 8,028 (2.3067%) |
| BOTH_TRUE_AND_FALSE | 8,982 | 700,505 | 91,623 | 7,094 (78.9802%) / 532,175 (75.9702%) | 1,146 (12.7589%) / 163,130 (23.2875%) | 742 (8.2610%) / 5,200 (0.7423%) |

`vulnerable`은 criteria identity가 아닌 usage stratification으로 처리했으며 false occurrence도 제외하지 않았다.

## E. Part × Coverage

| Group | Criteria | Occurrences | CVEs | Exact criteria/occ. | Same tuple criteria/occ. | Configuration-only criteria/occ. |
| --- | ---: | ---: | ---: | --- | --- | --- |
| a | 266,808 | 1,347,393 | 237,886 | 147,210 (55.1745%) / 909,882 (67.5291%) | 55,418 (20.7707%) / 319,431 (23.7073%) | 64,180 (24.0548%) / 118,080 (8.7636%) |
| o | 92,945 | 1,231,685 | 104,789 | 62,420 (67.1580%) / 933,810 (75.8157%) | 23,787 (25.5926%) / 270,757 (21.9826%) | 6,738 (7.2494%) / 27,118 (2.2017%) |
| h | 68,664 | 591,070 | 32,199 | 59,637 (86.8534%) / 569,860 (96.4116%) | 3,989 (5.8094%) / 8,834 (1.4946%) | 5,038 (7.3372%) / 12,376 (2.0938%) |
| other | 0 | 0 | 0 | 0 (0.0000%) / 0 (0.0000%) | 0 (0.0000%) / 0 (0.0000%) | 0 (0.0000%) / 0 (0.0000%) |

## F. Configuration-only Product Tuples

- Distinct product tuples: 31,895
- Distinct vendor values: 15,974
- Distinct product values: 30,450
- Part distribution: `{"a": 23073, "h": 3663, "o": 5159, "other": 0}`
- Unparseable criteria expressions in this class: 0

### Occurrence 기준 상위 30개

| part | vendor | product | criteria | occurrences | CVEs | vuln=true | vuln=false |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| o | sun | opensolaris | 450 | 11,327 | 115 | 11,321 | 6 |
| a | tor | tor | 258 | 5,411 | 57 | 5,411 | 0 |
| a | ethereal_group | ethereal | 58 | 1,889 | 105 | 1,889 | 0 |
| a | mantis | mantis | 99 | 1,231 | 46 | 1,169 | 62 |
| a | poppler | poppler | 73 | 1,020 | 28 | 1,019 | 1 |
| a | clam_anti-virus | clamav | 101 | 974 | 61 | 973 | 1 |
| h | cisco | ios_transmission_control_protocol | 263 | 947 | 4 | 947 | 0 |
| a | phpbb_group | phpbb | 47 | 932 | 82 | 931 | 1 |
| a | xine | xine-lib | 68 | 819 | 38 | 819 | 0 |
| a | francisco_burzi | php-nuke | 42 | 713 | 96 | 684 | 29 |
| a | oracle | oracle9i | 68 | 660 | 52 | 660 | 0 |
| a | joomla | joomla | 44 | 623 | 215 | 418 | 205 |
| a | punbb | punbb | 56 | 612 | 47 | 606 | 6 |
| a | squid | squid | 102 | 579 | 37 | 579 | 0 |
| o | arubanetworks | aos-cx | 1 | 532 | 12 | 532 | 0 |
| o | cisco | cisco_ios | 272 | 514 | 8 | 473 | 41 |
| a | gplhost | domain_technologie_control | 35 | 497 | 15 | 497 | 0 |
| a | jelsoft | vbulletin | 69 | 496 | 55 | 475 | 21 |
| a | f-secure | f-secure_anti-virus | 134 | 450 | 36 | 444 | 6 |
| a | asterisk | asterisk | 190 | 441 | 20 | 441 | 0 |
| a | hitachi | jp1_file_transmission_server | 242 | 417 | 3 | 417 | 0 |
| a | easy_software_products | cups | 59 | 411 | 35 | 411 | 0 |
| a | rob_flynn | gaim | 51 | 385 | 26 | 385 | 0 |
| a | simplemachines | smf | 64 | 368 | 9 | 368 | 0 |
| a | invision_power_services | invision_power_board | 45 | 366 | 42 | 358 | 8 |
| a | mybulletinboard | mybulletinboard | 44 | 347 | 63 | 334 | 13 |
| a | incogen | bugport | 109 | 336 | 4 | 327 | 9 |
| a | kerio | kerio_mailserver | 57 | 333 | 22 | 333 | 0 |
| a | kerio | winroute_firewall | 50 | 329 | 12 | 292 | 37 |
| a | oracle | oracle8i | 60 | 318 | 46 | 318 | 0 |

### Distinct CVE 기준 상위 30개

| part | vendor | product | criteria | occurrences | CVEs | vuln=true | vuln=false |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| a | joomla | joomla | 44 | 623 | 215 | 418 | 205 |
| a | microsoft | microsoft_365 | 1 | 170 | 170 | 170 | 0 |
| o | sun | opensolaris | 450 | 11,327 | 115 | 11,321 | 6 |
| a | ethereal_group | ethereal | 58 | 1,889 | 105 | 1,889 | 0 |
| a | francisco_burzi | php-nuke | 42 | 713 | 96 | 684 | 29 |
| a | phpbb_group | phpbb | 47 | 932 | 82 | 931 | 1 |
| o | ubuntu | ubuntu_linux | 48 | 241 | 75 | 188 | 53 |
| o | sco | unixware | 24 | 128 | 66 | 128 | 0 |
| a | mybulletinboard | mybulletinboard | 44 | 347 | 63 | 334 | 13 |
| o | qualcomm | qualcomm_215_firmware | 1 | 62 | 62 | 62 | 0 |
| a | clam_anti-virus | clamav | 101 | 974 | 61 | 973 | 1 |
| a | pcman | ftp_server | 2 | 59 | 59 | 59 | 0 |
| a | tor | tor | 258 | 5,411 | 57 | 5,411 | 0 |
| a | jelsoft | vbulletin | 69 | 496 | 55 | 475 | 21 |
| a | oracle | oracle9i | 68 | 660 | 52 | 660 | 0 |
| a | printerlogic | vasion_print | 1 | 49 | 49 | 49 | 0 |
| a | punbb | punbb | 56 | 612 | 47 | 606 | 6 |
| a | redhat | hardened_images | 1 | 47 | 47 | 47 | 0 |
| a | mantis | mantis | 99 | 1,231 | 46 | 1,169 | 62 |
| a | oracle | oracle8i | 60 | 318 | 46 | 318 | 0 |
| h | qualcomm | cologne | 1 | 45 | 45 | 0 | 45 |
| o | qualcomm | cologne_firmware | 1 | 45 | 45 | 45 | 0 |
| a | oracle | peoplesoft_and_jdedwards_product_suite | 41 | 169 | 44 | 169 | 0 |
| o | redhat | linux_desktop | 1 | 44 | 44 | 44 | 0 |
| o | redhat | linux_server | 1 | 44 | 44 | 44 | 0 |
| o | redhat | linux_workstation | 1 | 44 | 44 | 44 | 0 |
| a | invision_power_services | invision_power_board | 45 | 366 | 42 | 358 | 8 |
| a | mambo | mambo | 34 | 126 | 40 | 112 | 14 |
| o | unix | unix | 2 | 41 | 40 | 2 | 39 |
| a | postnuke_software_foundation | postnuke | 31 | 89 | 39 | 88 | 1 |

`Configuration-only product tuple`은 invalid CPE 또는 Dictionary omission을 뜻하지 않는다.

## G. Representative Cases

### EXACT_PRESENT (최대 10)

| criteria | part/vendor/product/version | range | vulnerable | occurrences | CVEs | exact | tuple A/D |
| --- | --- | --- | --- | ---: | ---: | --- | ---: |
| cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:* | o/microsoft/windows/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 10,249 | 8,635 | ACTIVE | 9/16 |
| cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:* | o/microsoft/windows_server_2012/r2 | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 4,555 | 4,359 | ACTIVE | 25/4 |
| cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:* | o/microsoft/windows_server_2012/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 4,363 | 4,137 | ACTIVE | 25/4 |
| cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:* | o/apple/macos/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 4,339 | 3,767 | ACTIVE | 161/13 |
| cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:* | o/linux/linux_kernel/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 4,259 | 3,746 | ACTIVE | 6,270/135 |
| cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:* | o/debian/debian_linux/9.0 | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 4,020 | 4,003 | ACTIVE | 64/1 |
| cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:* | a/netapp/oncommand_insight/- | NO_RANGE_ONLY | TRUE_ONLY | 963 | 963 | ACTIVE | 31/0 |
| cpe:2.3:h:qualcomm:wcd9380:-:*:*:*:*:*:*:* | h/qualcomm/wcd9380/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 1,205 | 1,205 | ACTIVE | 1/0 |
| cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:* | o/microsoft/windows_10/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 2,833 | 2,660 | DEPRECATED | 2/57 |
| cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:* | o/microsoft/windows_server_2019/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 3,168 | 3,051 | ACTIVE | 217/0 |

### EXACT_ABSENT + SAME_PRODUCT_TUPLE_PRESENT (최대 20)

| criteria | part/vendor/product/version | range | vulnerable | occurrences | CVEs | exact | tuple A/D |
| --- | --- | --- | --- | ---: | ---: | --- | ---: |
| cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:* | o/linux/linux_kernel/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 51,458 | 14,306 | ABSENT | 6,270/135 |
| cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:* | a/google/chrome/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 6,037 | 5,810 | ABSENT | 9,532/0 |
| cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:* | o/apple/macos/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 4,836 | 2,938 | ABSENT | 161/13 |
| cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:* | o/apple/iphone_os/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 4,608 | 4,245 | ABSENT | 329/2 |
| cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:* | o/apple/mac_os_x/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 4,145 | 3,315 | ABSENT | 216/0 |
| cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:* | o/microsoft/windows/* | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 2,123 | 1,524 | ABSENT | 9/16 |
| cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:* | a/microsoft/internet_explorer/11 | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 210 | 204 | ABSENT | 108/1 |
| cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:* | a/gitlab/gitlab/* | RANGE_ONLY | TRUE_ONLY | 3,282 | 1,327 | ABSENT | 3,128/38 |
| cpe:2.3:o:microsoft:windows_server_2008:-:-:*:*:*:*:*:* | o/microsoft/windows_server_2008/- | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 57 | 32 | ABSENT | 122/19 |
| cpe:2.3:h:cisco:5500_series_adaptive_security_appliance:*:*:*:*:*:*:*:* | h/cisco/5500_series_adaptive_security_appliance/* | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 58 | 52 | ABSENT | 2/0 |
| cpe:2.3:a:mozilla:firefox_esr:*:*:*:*:*:*:*:* | a/mozilla/firefox_esr/* | RANGE_ONLY | TRUE_ONLY | 443 | 432 | ABSENT | 0/203 |
| cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:* | a/mozilla/firefox/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 2,803 | 2,312 | ABSENT | 1,037/159 |
| cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:* | a/gitlab/gitlab/* | RANGE_ONLY | TRUE_ONLY | 2,793 | 1,116 | ABSENT | 3,128/38 |
| cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:* | o/apple/ipados/* | RANGE_ONLY | TRUE_ONLY | 2,454 | 2,038 | ABSENT | 138/0 |
| cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:classic:*:*:* | a/adobe/acrobat_dc/* | RANGE_ONLY | TRUE_ONLY | 2,383 | 1,401 | ABSENT | 251/2 |
| cpe:2.3:a:adobe:acrobat_reader_dc:*:*:*:*:classic:*:*:* | a/adobe/acrobat_reader_dc/* | RANGE_ONLY | TRUE_ONLY | 2,380 | 1,400 | ABSENT | 242/3 |
| cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:* | o/microsoft/windows_server_2022/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 2,278 | 2,264 | ABSENT | 341/6 |
| cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:* | o/microsoft/windows_server_2019/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 2,186 | 2,178 | ABSENT | 217/0 |
| cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:* | o/microsoft/windows_server_2016/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 2,156 | 2,152 | ABSENT | 72/6 |
| cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:* | o/apple/tvos/* | RANGE_ONLY | BOTH_TRUE_AND_FALSE | 2,079 | 2,077 | ABSENT | 123/3 |

### EXACT_ABSENT + SAME_PRODUCT_TUPLE_ABSENT (최대 30)

| criteria | part/vendor/product/version | range | vulnerable | occurrences | CVEs | exact | tuple A/D |
| --- | --- | --- | --- | ---: | ---: | --- | ---: |
| cpe:2.3:o:arubanetworks:aos-cx:*:*:*:*:*:*:*:* | o/arubanetworks/aos-cx/* | RANGE_ONLY | TRUE_ONLY | 532 | 12 | ABSENT | 0/0 |
| cpe:2.3:a:microsoft:microsoft_365:-:*:*:*:*:macos:*:* | a/microsoft/microsoft_365/- | NO_RANGE_ONLY | TRUE_ONLY | 170 | 170 | ABSENT | 0/0 |
| cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:* | a/joomla/joomla/* | BOTH_RANGE_AND_NO_RANGE | BOTH_TRUE_AND_FALSE | 164 | 163 | ABSENT | 0/0 |
| cpe:2.3:o:arubanetworks:aos-cx_firmware:*:*:*:*:*:*:*:* | o/arubanetworks/aos-cx_firmware/* | RANGE_ONLY | TRUE_ONLY | 84 | 3 | ABSENT | 0/0 |
| cpe:2.3:o:bender:icc15xx_firmware:*:*:*:*:*:*:*:* | o/bender/icc15xx_firmware/* | RANGE_ONLY | TRUE_ONLY | 80 | 8 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.7:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.7 | NO_RANGE_ONLY | TRUE_ONLY | 63 | 63 | ABSENT | 0/0 |
| cpe:2.3:h:qualcomm:cologne:-:*:*:*:*:*:*:* | h/qualcomm/cologne/- | NO_RANGE_ONLY | FALSE_ONLY | 45 | 45 | ABSENT | 0/0 |
| cpe:2.3:o:unix:unix:*:*:*:*:*:*:*:* | o/unix/unix/* | NO_RANGE_ONLY | BOTH_TRUE_AND_FALSE | 37 | 36 | ABSENT | 0/0 |
| cpe:2.3:o:lexmark:lw80_firmware:*:*:*:*:*:*:*:* | o/lexmark/lw80_firmware/* | RANGE_ONLY | TRUE_ONLY | 75 | 5 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.3:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.3 | NO_RANGE_ONLY | TRUE_ONLY | 62 | 62 | ABSENT | 0/0 |
| cpe:2.3:o:qualcomm:qualcomm_215_firmware:-:*:*:*:*:*:*:* | o/qualcomm/qualcomm_215_firmware/- | NO_RANGE_ONLY | TRUE_ONLY | 62 | 62 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.1:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.1 | NO_RANGE_ONLY | TRUE_ONLY | 61 | 61 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.2:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.2 | NO_RANGE_ONLY | TRUE_ONLY | 61 | 61 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.6:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.6 | NO_RANGE_ONLY | TRUE_ONLY | 61 | 61 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.4:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.4 | NO_RANGE_ONLY | TRUE_ONLY | 60 | 60 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.5:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.5 | NO_RANGE_ONLY | TRUE_ONLY | 58 | 58 | ABSENT | 0/0 |
| cpe:2.3:a:ethereal_group:ethereal:0.10.8:*:*:*:*:*:*:* | a/ethereal_group/ethereal/0.10.8 | NO_RANGE_ONLY | TRUE_ONLY | 58 | 58 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_69:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_69 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_70:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_70 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_72:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_72 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_73:*:sparc:*:*:*:*:* | o/sun/opensolaris/snv_73 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_73:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_73 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_74:*:sparc:*:*:*:*:* | o/sun/opensolaris/snv_74 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_74:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_74 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_75:*:sparc:*:*:*:*:* | o/sun/opensolaris/snv_75 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_76:*:sparc:*:*:*:*:* | o/sun/opensolaris/snv_76 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_76:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_76 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_77:*:sparc:*:*:*:*:* | o/sun/opensolaris/snv_77 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_77:*:x86:*:*:*:*:* | o/sun/opensolaris/snv_77 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |
| cpe:2.3:o:sun:opensolaris:snv_78:*:sparc:*:*:*:*:* | o/sun/opensolaris/snv_78 | NO_RANGE_ONLY | TRUE_ONLY | 57 | 57 | ABSENT | 0/0 |

## H. Interpretation

1. Dictionary exact CPE로 존재하는 비율은 expression 기준 62.85161420%, occurrence 기준 76.13373256%다.
2. Exact-absent 중 동일 product tuple이 존재하는 비율은 expression 기준 52.27395539%, occurrence 기준 79.17329724%다.
3. Product tuple도 Dictionary에 없는 표현은 75,956개 (17.72945518%), 157,574 occurrences (4.97055658%)다.
4. Concrete/wildcard/range, vulnerable usage, part별 차이는 위 표와 `summary.json`의 class별 expression/usage/CVE 지표로 분리했다.
5. Dictionary만으로 향후 후보 공간을 제한하기 전에는 Configuration-only tuple의 source/provenance, escaped-field grammar, deprecated replacement, 그리고 range-to-version 관계를 별도 단계에서 검증해야 한다. 이번 분석에서는 어느 것도 평가하지 않았다.

## Artifacts

- `summary.json`: 전체 집계와 대표 사례
- `criteria_coverage.csv.gz`: 428,417 expression rows, SHA-256 `90f3a9fca2e0982300eb8a8b42be73062cd6cfe9b0e2c5c2e77d980cff1e2ecf`

## Safety

- PostgreSQL READ ONLY transactions: `true`
- DB writes: `0`
- 작업 전후 전체 table counts와 NVD/CPE snapshot metadata 동일: `true`
- Coverage invariants passed: `true`
- Models/migrations/API/UI/matching logic 변경: 없음
