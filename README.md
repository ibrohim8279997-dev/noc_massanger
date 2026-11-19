# noc_massanger

Приватный мессенджер для узкого круга людей. Подробности: `docs/architecture.md`, `docs/threat-model.md`, `docs/decisions/`.

## Статус
| Часть | Состояние |
|---|---|
| server/ (этап 1) | готово, 31 тест: `cd server && pip install -r requirements-dev.txt && python -m pytest` |
| client-android/core-crypto (этап 1) | готово, 20 тестов: `cd client-android && gradle test` |
| Android-приложение (UI, Keystore, SQLCipher, биометрия) | не начато: нужен Android SDK |
| Этапы 2, 3, 4 | не начаты |

Отчёты: `docs/security-checks/`.
