# noc_massanger

Приватный мессенджер для узкого круга людей. Подробности: `docs/architecture.md`, `docs/threat-model.md`, `docs/decisions/`.

## Статус
| Часть | Состояние |
|---|---|
| server/ (этап 1) | готово, 31 тест: `cd server && pip install -r requirements-dev.txt && python -m pytest` |
| client-android/core-crypto (этап 1) | готово, 25 тестов: `cd client-android && gradle :core-crypto:test` |
| Android-приложение (этап 1) | собирается (`ANDROID_HOME=... gradle :app:assembleRelease`), на устройстве не проверено |
| Этапы 2, 3, 4 | не начаты |

Отчёты: `docs/security-checks/`.
