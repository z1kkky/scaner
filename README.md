# scaner

Сканер безопасности сайтов малого бизнеса: вводишь домен — получаешь понятный отчёт
о проблемах, чем они грозят и как их исправить.

Сейчас это CLI с одной проверкой (заголовки безопасности). Дальше сюда добавятся
SSL/TLS, почта (SPF/DKIM/DMARC), порты, открытые файлы, CMS и шаблоны Nuclei,
а сам сканер станет gRPC-сервисом.

> ⚠️ Только неинвазивные проверки. Сканируйте только свои домены или домены,
> владелец которых дал согласие.

## Быстрый старт

Нужен Go 1.24+ ([установка](https://go.dev/dl/)).

```bash
git clone https://github.com/z1kkky/scaner.git
cd scaner

# запустить без сборки
go run ./cmd/scanner example.com

# с другим таймаутом на каждую проверку (по умолчанию 10s)
go run ./cmd/scanner -timeout 20s example.com

# собрать бинарник и запустить его
go build -o scanner ./cmd/scanner
./scanner example.com

# тесты
go test ./...
```

Можно передать и URL целиком (`https://example.com/page`) — сканер сам оставит домен.

## Пример вывода

```json
{
  "domain": "example.com",
  "started_at": "2026-11-08T06:24:11Z",
  "duration_ms": 195,
  "results": [
    {
      "check": "headers",
      "findings": [
        {
          "check": "headers",
          "title": "Нет заголовка HSTS",
          "severity": "medium",
          "description": "Браузер может открыть сайт по незащищённому HTTP...",
          "fix": "Добавьте заголовок: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        }
      ],
      "duration_ms": 195
    }
  ]
}
```

## Структура

```
cmd/scanner/main.go        точка входа: разбор аргументов, запуск, вывод JSON
internal/check/check.go    интерфейс Check и структура Finding
internal/check/headers.go  проверка заголовков HSTS, CSP, X-Frame-Options, X-Content-Type-Options
internal/runner/runner.go  параллельный запуск проверок в горутинах с таймаутами
```

`internal/` — особая папка в Go: её пакеты можно импортировать только внутри этого репозитория.

## Как добавить новую проверку

1. Создайте файл в `internal/check/`, например `tls.go`.
2. Объявите тип и два метода — `Name() string` и `Run(ctx, domain) []Finding`.
   Этого достаточно, чтобы тип подходил под интерфейс `Check`.
3. Передавайте `ctx` во все сетевые вызовы — так сработает таймаут.
4. Добавьте проверку в список `checks` в `cmd/scanner/main.go`.
5. Напишите тест рядом (`tls_test.go`) и запустите `go test ./...`.
