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
| Этап 4 (mesh) | логика проверена симуляцией (44 теста, 10 проверок); Bluetooth-код написан, на устройствах не проверен; Wi-Fi Direct не сделан: `tools/stage4_checks.sh` |

Отчёты: `docs/security-checks/`.
