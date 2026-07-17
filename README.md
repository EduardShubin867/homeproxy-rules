# HomeProxy combined rules

Один автоматически обновляемый `.srs` для HomeProxy / sing-box 1.12.x.

## Что входит

- Re:filter — домены и IP-адреса;
- Telegram — домены и IP-адреса;
- OpenAI — домены;
- Anthropic / Claude — домены;
- собственные дополнения из `custom/include-*`;
- собственные исключения из `custom/exclude-*`.

GitHub Actions проверяет upstream-источники каждые 6 часов, объединяет их,
удаляет дубли и собирает один файл:

```text
dist/homeproxy.srs
```

## URL для HomeProxy

После первого успешного запуска workflow:

```text
https://raw.githubusercontent.com/OWNER/REPOSITORY/main/dist/homeproxy.srs
```

Для репозитория `EduardShubin867/homeproxy-rules` это будет:

```text
https://raw.githubusercontent.com/EduardShubin867/homeproxy-rules/main/dist/homeproxy.srs
```

В HomeProxy укажите:

```text
Type: Remote
Format: Binary
URL: ссылка выше
Update interval: 6h
```

И направьте этот rule set в нужный proxy outbound.

## Добавление доменов

`custom/include-domains.txt`:

```text
example.com
full:api.example.net
keyword:example
regexp:^stun\..+
```

Обычный `example.com` соответствует самому домену и всем его поддоменам.

## Добавление IP

`custom/include-ips.txt`:

```text
203.0.113.10
198.51.100.0/24
```

## Исключения

Исключения встроены внутрь того же единственного `.srs` через логическое правило:

```text
(include) AND NOT (exclude)
```

Поэтому можно исключить дочерний домен, даже если upstream содержит широкий
`domain_suffix`, либо исключить маленькую IP-подсеть из более широкой.

`custom/exclude-domains.txt`:

```text
twitch.tv
full:api.example.com
```

`custom/exclude-ips.txt`:

```text
203.0.113.0/24
```

## Совместимость

Сборка намеренно закреплена на sing-box `1.12.17`, как на роутере.
Выходной source format — версия `3`, поддерживаемая sing-box 1.12.x.

После обновления sing-box на роутере версию можно поменять в:

```text
.github/workflows/build.yml
```

## Ручной запуск

```bash
python3 scripts/build.py --sing-box /path/to/sing-box
```

Временные файлы сохраняются в `.work/`, итог — в `dist/`.
