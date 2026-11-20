# noc_massanger

Приватный мессенджер для узкого круга людей. Подробности: `docs/architecture.md`, `docs/threat-model.md`, `docs/decisions/`.

## Статус
| Часть | Состояние |
|---|---|
| server/ (этапы 1 и 2) | готово, 43 теста: `cd server && pip install -r requirements-dev.txt && python -m pytest` |
| client-android/core-crypto, core-client, core-mesh | готово, 96 тестов (включая сквозные на настоящем сервере): `cd client-android && gradle :core-crypto:test :core-client:test` |
| Android-приложение (этап 1) | собирается (`ANDROID_HOME=... gradle :app:assembleRelease`), на устройстве не проверено |
| Этап 2 (Tor, cover traffic, ящики, группы) | реализован и проверен тестами; Tor на устройстве и мосты не проверены: `docs/security-checks/stage2.md`, `tools/stage2_checks.sh` |
| Этап 3 (сервер, суперадмин, фаервол) | реализован; фаервол проверен в сетевых пространствах, на телефоне нет: `tools/stage3_checks.sh` |
| Этап 4 (mesh) | логика проверена симуляцией и по TCP (17 проверок, 119 тестов); Bluetooth, Wi-Fi Direct и Nearby написаны, на устройствах не проверены: `tools/stage4_checks.sh` |
| ML-DSA-65 суперадмина (liboqs) | гибрид с Ed25519, 13 проверок: `tools/pq_checks.sh` |

Отчёты: `docs/security-checks/`.
