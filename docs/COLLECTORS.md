# Коллекторы NodeTrace IR

## Общая модель

Коллекторы работают последовательно, не запускают подозрительный файл, не выполняют ремедиацию и не удаляют данные. Каждый источник возвращает факты, связи, gaps и техническую сводку. Состав зависит от режима цели.

В live-режиме нет облачной отправки, внешних API или активного сетевого сканирования; сетевой коллектор читает локальное состояние. Однако UNC-пути и системная проверка доверия подписи могут инициировать сетевую активность самой Windows. Live-response не является форензически read-only: запуск процессов, чтение файлов и запись рабочего хранилища меняют состояние работающего узла.

В WinPE/offline-режиме `offline_root` указывает на смонтированную отключённую Windows, а `data_dir` обязан находиться на отдельном writable-томе. Live-процессы, сеть и persistence API среды WinPE не собираются и не приписываются цели.

### Live-профиль

| Порядок | Имя | Основной источник | Что даёт |
|---:|---|---|---|
| 1 | `file_seed` | файл, NTFS ADS, Authenticode | идентичность и provenance файла-зерна |
| 2 | `live_processes` | `Win32_Process` | текущие процессы и parent PID |
| 3 | `network` | `Get-NetTCPConnection`, DNS cache | текущие TCP-соединения, endpoints и DNS-кэш |
| 4 | `persistence` | Registry, services, tasks, Startup | текущие механизмы закрепления |
| 5 | `event_logs` | Windows Event Logs | ретроспективная временная шкала доступных событий |
| 6 | `filesystem_context` | ограниченный обход каталогов | файлы, близкие по timestamp |
| 7 | `prefetch` | metadata имён `.pf` | возможный след исполнения по имени EXE |

### Offline-профиль

| Порядок | Имя | Основной источник | Что даёт |
|---:|---|---|---|
| 1 | `file_seed` | доступный файл, ADS, hashes | идентичность и provenance файла-зерна |
| 2 | `offline_browser_downloads` | Edge/Chrome `History` | сохранённые download rows и точные URL-цепочки |
| 3 | `offline_usb_history` | `Windows\INF\setupapi.dev.log` | точные исторические USB instance IDs |
| 4 | `event_logs` | файлы EVTX отключённой Windows | постоянная событийная телеметрия |
| 5 | `prefetch` | metadata `.pf` отключённой Windows | возможный след исполнения по имени |
| 6 | `offline_coverage` | границы режима | явные gaps для процессов, сети и памяти |

`offline_browser_downloads` сопоставляет запись с drive-neutral путём файла и сохраняет всю доступную URL-цепочку, но не утверждает равенство байтов без независимого хэша. `offline_usb_history` перечисляет точные идентификаторы устройств, но намеренно не создаёт связь USB → файл только по близкому времени: SetupAPI фиксирует установку устройства, а не операцию копирования.

## 1. `file_seed`

### Источники

- `stat` обычного файла;
- один потоковый read для SHA-256, SHA-1 и MD5;
- NTFS alternate data stream `Zone.Identifier`;
- `Get-AuthenticodeSignature`.

### Результат

- объект `file` со stable key `file:sha256:<digest>`;
- размер, путь, расширение и временные метки;
- при наличии — объект `alternate_data_stream` и связь `has_alternate_stream`;
- объект `authenticode_signature` и связь `has_signature_state`.

### Ограничения

Файл читается целиком, но не исполняется и не импортируется. Хэш идентифицирует содержимое, но не определяет его вредоносность. Authenticode сообщает состояние подписи на момент запроса; валидная подпись не гарантирует безопасность, а реализация проверки доверия в Windows может обращаться к настроенным службам проверки сертификатов. `Zone.Identifier` может отсутствовать или быть удалён. На не-NTFS носителе ADS недоступен.

## 2. `live_processes`

### Источник

`Get-CimInstance -ClassName Win32_Process`:

- PID/PPID;
- имя, executable path и command line;
- creation time, session ID;
- handles, threads и working set.

### Результат

- объект `process` на каждый доступный текущий процесс;
- связь `reported_parent_of`, если оба PID присутствуют в снимке.

### Ограничения

Это одномоментный live-снимок, а не история. Завершившиеся процессы отсутствуют. PID мог быть переиспользован, поэтому parent relation имеет `medium`. Без администратора executable path и command line отдельных процессов могут быть пустыми. Скрытый rootkit процесс может не отображаться.

## 3. `network`

### Источники

- `Get-NetTCPConnection`;
- `Win32_Process` для сопоставления PID;
- `Get-DnsClientCache`.

### Результат

- `network_connection` с local/remote endpoint, state и PID;
- `network_endpoint` для удалённой стороны;
- `dns_cache_record`;
- `owns_connection` и `remote_endpoint`.

### Ограничения

Коллектор не инициирует соединения и не делает DNS lookup — он читает локальное текущее состояние. Уже закрытые соединения отсутствуют. DNS-кэш не показывает процесс, который создал запись, и может содержать легитимные/общесистемные данные. PID ownership достоверен для снимка, но не доказывает, что соединение создано исследуемым файлом.

## 4. `persistence`

### Источники

- HKLM/HKCU `Run` и `RunOnce`, включая `WOW6432Node`;
- `Win32_Service`;
- `Get-ScheduledTask` и действия задач;
- пользовательский и общесистемный Startup folders.

### Результат

- `run_key_value`;
- `windows_service`;
- `scheduled_task`;
- `startup_item`;
- `possible_persistence_reference`, если команда содержит полный нормализованный путь (`high`) или только имя подозрительного файла (`medium`).

### Ограничения

Это текущая инвентаризация, не история изменений. Совпадение строки команды не доказывает выполнение. Одинаковые имена файлов создают неоднозначность. Коллектор не покрывает все возможные методы persistence: WMI subscriptions, drivers, COM hijacking, AppInit, IFEO, LSA packages и другие техники требуют отдельных источников.

## 5. `event_logs`

### Источники и event IDs

| Поток | Log | IDs |
|---|---|---|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | 1, 3, 7, 11, 12, 13, 14, 22, 23, 26 |
| Process creation | `Security` | 4688 |
| Defender | `Microsoft-Windows-Windows Defender/Operational` | 1006, 1007, 1008, 1116–1120, 5007, 5010, 5012 |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | 4104 |
| Service install | `System` | 7045 |
| Task Scheduler | `Microsoft-Windows-TaskScheduler/Operational` | 106, 129, 140–142, 200, 201 |

### Результат

Каждое событие становится `windows_event` с log name, event/record ID, provider, level, machine, process/thread ID и сообщением (не более 20 000 символов). Источник адресуется как `<log>#<record-id>`.

### Значения по умолчанию

- глубина GUI/CLI — 7 дней;
- максимум — 500 событий на поток;
- timeout общего запроса — 120 секунд.

### Ограничения

Журнал мог быть не установлен, отключён, очищен или перезаписан. Не включённый заранее Sysmon/4688/4104 не может записать прошлое задним числом. `MaxEvents` усекает очень активные журналы. Текущая версия сохраняет событие как факт, но не извлекает из каждого XML все сущности и причинные связи автоматически.

## 6. `filesystem_context`

### Область по умолчанию

- каталог подозрительного файла;
- `%TEMP%`;
- Startup folder текущего пользователя;
- общесистемный Startup folder.

Ограничения обхода:

- глубина — 2;
- максимум — 3000 directory entries;
- временное окно — ±24 часа от modification time файла-зерна.

### Результат

- `filesystem_context_file` с путём, размером и timestamps;
- `temporally_adjacent_file` с `low` и точной дельтой времени.

Содержимое соседних файлов не читается (`content_not_read=true`).

### Ограничения

Временная близость не доказывает создание или изменение исследуемым файлом. Обход не является полным дисковым поиском, не читает MFT/USN и может быть усечён. Права, junctions, отсутствующие профили и изменённые timestamps уменьшают покрытие.

## 7. `prefetch`

### Источник

Метаданные файлов `%SystemRoot%\Prefetch\<EXE>-*.pf` либо отдельно указанного каталога.

### Результат

- `prefetch_metadata` с path, размером и timestamps;
- `possible_prefetch_name_match` с `medium`.

### Ограничения

Содержимое `.pf` не парсится (`content_parsed=false`). Совпадение строится только по имени EXE и не доказывает полный исходный путь, конкретный SHA-256 или то, что текущий файл является тем же содержимым. Prefetch может быть отключён, очищен или недоступен. Максимум по умолчанию — 20 000 записей.

## Настраиваемые опции

CLI напрямую открывает только `--lookback`. Остальные опции доступны программному вызывающему коду через `CollectionEngine.run(..., options={...})`:

| Опция | Default | Диапазон/смысл |
|---|---:|---|
| `event_max_per_log` | 500 | 1–5000 событий на поток |
| `event_timeout_seconds` | 120 | 10–600 секунд |
| `filesystem_max_entries` | 3000 | 10–50000 entries |
| `filesystem_max_depth` | 2 | 0–5 |
| `filesystem_time_window_hours` | 24 | 0.1–720 часов |
| `prefetch_directory` | `%SystemRoot%\Prefetch` | путь к live или смонтированному набору |
| `prefetch_max_entries` | 20000 | 100–100000 entries |
| `offline_browser_max_databases` | 64 | 1–512 Chromium History databases |
| `offline_browser_max_rows_per_database` | 500 | 1–5000 download rows на базу |
| `offline_browser_max_url_chain` | 32 | 1–128 URL на одну загрузку |
| `offline_usb_max_devices` | 512 | 1–5000 уникальных USB instance IDs |

Увеличение лимитов повышает полноту, но также время, нагрузку и объём чувствительных данных. Любое достижение лимита должно создавать gap.

## Как читать результат

- Успешный коллектор означает только, что запрос завершился и его результат сохранён.
- Пустой результат означает «в доступной выборке ничего не найдено», а не «события никогда не было».
- `partial` означает, что часть источника ограничена либо присутствуют gaps.
- Связи `medium` и `low` — направления проверки, а не готовые выводы.
- На заражённом live-узле все API-ответы требуют независимой валидации.

Семантика полей и правила формулирования выводов описаны в [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md).
