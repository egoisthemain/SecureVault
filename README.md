### SecureVault - Сервис шифрования секретов на Go

Стек: Go, AES-256-GCM, PostgreSQL, pgx, Docker Compose.

Проект реализует модель шифрования и хранения секретов в базе данных.

Полные маршруты и назначение:
| Метод и путь | Действие |
| --- | --- |
| POST /secrets	| Создать секрет, вернуть ID |
| GET /secrets/{id} |	Получить исходное значение |
| DELETE /secrets/{id} | Удалить секрет |

и требование авторизации запроса: `Authorization: Bearer <токен>`

Используемые переменные окружения: 
- HTTP_ADDR - адрес http
- DATABASE_URL - подключение приложения к PostgreSQL.
- TEST_DATABASE_URL — подключение интеграционных тестов.
- KEY_ID - идентификатор ключа, не сам ключ.
- ENCRYPTION_KEY - 32 байта ключа, представленные 64 hex-символами.
- API_TOKEN - отдельный токен доступа.

Порядок запуска: PostgreSQL → применение миграции → загрузка настроек → сборка и запуск.

Команды запуска: (команды выполняются из корня проекта в Git Bash)

``` bash
    docker compose up -d db
```
для sql:
``` bash
    docker compose exec db psql -U securevault -d securevault
```
Внутри psql нужно выполнить содержимое **migrations/001_create_secrets.sql**, затем выйти через **\q**

Создание файла .env(Пример):
``` dotenv
HTTP_ADDR=127.0.0.1:18080
DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:15432/securevault?sslmode=disable
KEY_ID=local-key-v1
ENCRYPTION_KEY=REPLACE_WITH_GENERATED_KEY
API_TOKEN=REPLACE_WITH_SEPARATELY_GENERATED_TOKEN
```

Настройка, сборка, запуск:
``` bash
set -a
source .env
set +a

go build -o securevault.exe ./cmd/securevault
./securevault.exe
```

- USER и PASSWORD берутся из локального compose.yaml;
- ключ и токен — результаты двух отдельных запусков go run ./cmd/keygen;
- заполнители нужно заменить перед запуском;
- .env исключён из Git и не должен попадать в коммиты.

Реализованы обычные и интеграционные тесты для проверки работы сервиса.
``` bash
    go test ./...
```
При отсутствии TEST_DATABASE_URL тесты PostgreSQL пропускаются, поэтому общий PASS не подтверждает проверку БД. Для неё переменную нужно задать и запустить:
``` bash
    go test ./internal/storage -v -count=1
```

файл **.env** предварительно создается локально и Go автоматически его не читает. 

Для первого запуска генерируется два независимых значения через **go run ./cmd/keygen**.
При последующих запусках ключ нужно оставлять прежним, чтобы сохранить возможность расшифрования.

Текущие ограничения: один ключ, один общий API-токен, отсутствие разделения прав пользователей, HTTP только для локального запуска.

Напоминание: потеря ключа делает сохранённые секреты недоступными для расшифрования.