# Обновление баз AVZ для NodeTrace IR

## Коротко

База AVZ обновляется **на доверенной машине сборки**, а не внутри загрузочного
WinPE во время расследования. После обновления формируется новый read-only ISO
с новым опубликованным SHA-256. Такой порядок сохраняет воспроизводимость
носителя и не создаёт сетевую активность от заражённого узла.

Официальная полная база AVZ публикуется по изменяемому адресу
`https://z-oleg.com/secur/avz_up/avzbase.zip`. По информации автора AVZ,
полная база обновляется два раза в сутки: [страница загрузки AVZ](https://z-oleg.com/secur/avz/download.php).
В AVZ также есть штатный механизм обновления: [описание обновления баз](https://z-oleg.com/secur/avz_doc/avz_avupdate.htm).

Важно: HTTPS подтверждает канал загрузки, но изменяемый архив полной базы не
имеет опубликованной сильной подписи для автоматического доверия новому
содержимому. Поэтому NodeTrace IR применяет двухэтапную схему
`candidate -> review -> explicit re-pin`.

## 1. Получить и проверить кандидат

Из корня репозитория:

```powershell
python .\tools\update_avz_base.py `
  --accept-noncommercial-license
```

Команда:

- разрешает только официальный HTTPS-хост `z-oleg.com`;
- ограничивает размер загрузки, количество файлов и объём распаковки;
- запрещает traversal, дубликаты, каталоги и шифрованные ZIP-элементы;
- принимает только плоский набор `*.avz`;
- полностью читает каждый элемент и вычисляет SHA-256/CRC-32;
- вычисляет SHA-256/MD5 всего архива;
- создаёт `tools/cache/avzbase.candidate.zip` и
  `tools/avz-manifest.candidate.json`;
- не изменяет действующую базу и действующий manifest.

Если Python не доверяет корпоративному TLS-корню, загрузите **тот же точный
официальный URL** одобренным средством и передайте файл как локальный кандидат:

```powershell
Start-BitsTransfer `
  -Source "https://z-oleg.com/secur/avz_up/avzbase.zip" `
  -Destination ".\avzbase.downloaded.zip"

python .\tools\update_avz_base.py `
  --accept-noncommercial-license `
  --source-archive .\avzbase.downloaded.zip
```

Локальный файл проходит те же структурные и криптографические проверки. Сам
факт локальной загрузки не считается доказательством происхождения — оператор
отдельно проверяет URL и журнал корпоративного загрузчика.

## 2. Просмотреть изменения

Проверьте вывод SHA-256 и diff manifest до принятия кандидата:

```powershell
$baseSha = (Get-FileHash `
  .\tools\cache\avzbase.candidate.zip `
  -Algorithm SHA256).Hash
$manifestSha = (Get-FileHash `
  .\tools\avz-manifest.candidate.json `
  -Algorithm SHA256).Hash

$baseSha
$manifestSha

git diff --no-index `
  .\tools\avz-manifest.json `
  .\tools\avz-manifest.candidate.json
```

Если `git` отсутствует, оба JSON можно сравнить любым доверенным diff-инструментом.
Убедитесь, что кандидат изменяет только запись `avzbase.zip`; закреплённый
runtime `avz4.zip` не должен изменяться этим процессом.

## 3. Явно закрепить проверенную пару

```powershell
python .\tools\update_avz_base.py `
  --accept-noncommercial-license `
  --approve-repin `
  --expected-base-sha256 $baseSha `
  --expected-manifest-sha256 $manifestSha
```

При `--approve-repin` повторная загрузка не выполняется. Утилита заново
проверяет существующие candidate ZIP и candidate manifest, убеждается, что
оба SHA-256 совпадают со значениями из завершённого просмотра, архивирует
прежнюю базу и manifest в `tools/history/<UTC timestamp>/`, затем устанавливает
новую пару. Два файла файловой системы нельзя заменить одной атомарной
операцией: если процесс прервётся между заменами, `fetch_avz.ps1 -VerifyOnly`
обнаружит несогласованную пару и сборка завершится ошибкой. Для восстановления
используйте сохранённую полную пару из `tools/history/`.

## 4. Повторно проверить закреплённые входы

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\tools\fetch_avz.ps1 `
  -AcceptNonCommercialLicense `
  -VerifyOnly
```

Ожидаемый результат — успешная проверка размера, внешних хэшей и каждого
ZIP-элемента для `avz4.zip` и `avzbase.zip`.

## 5. Пересобрать и проверить ISO

Новая база попадёт на носитель только после новой сборки. Используйте
`scripts/build_winpe_iso_portable.ps1` с проверенными x86 WinPE-входами, затем:

```powershell
python .\scripts\verify_bootable_iso.py `
  .\dist\NodeTraceIR-AVZ-0.3.0-Bootable-x86.iso `
  --expect-path BOOTMGR `
  --expect-path BOOT/BCD `
  --expect-path BOOT/BOOT.SDI `
  --expect-path SOURCES/BOOT.WIM

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\smoke_test_winpe_vm.ps1 `
  -IsoPath .\dist\NodeTraceIR-AVZ-0.3.0-Bootable-x86.iso `
  -BuildRoot .\build\vm-smoke
```

После успешной проверки опубликуйте новый SHA-256 ISO. Уже выданный read-only
ISO не меняется задним числом и остаётся воспроизводимым доказательным входом.

## Откат

Предыдущие одобренные `avzbase.zip` и `avz-manifest.json` сохраняются в
`tools/history/`. Для отката остановите сборку, отдельно проверьте нужную
архивную пару, восстановите её в `tools/cache/avzbase.zip` и
`tools/avz-manifest.json`, выполните `fetch_avz.ps1 -VerifyOnly` и выпустите
новый ISO с новым номером/хэшем. Не заменяйте файл уже опубликованного релиза.

## Почему нет кнопки «обновить» в WinPE

WinPE-режим запускает AVZ и расследование автоматически и не требует кнопок.
Сетевое обновление в этот момент смешало бы сбор доказательств с изменением
инструмента, сделало бы два запуска несопоставимыми и могло бы раскрыть
активность заражённого узла. Обновление баз поэтому является отдельной
операцией сопровождения сборки.
