# Multi-Scanner & Risk Assessment Platform — Project Plan (v2)

> Статус: переработанная версия. Синхронизирована с фактическим состоянием кода на момент обновления.
> Область базового плана: статический анализ PE (`.exe`, `.dll`, `.sys`) и ZIP-бандлов. Веб-проверки описаны и отслеживаются отдельно в [WEB_SERVICE_INTEGRATION_PLAN.md](WEB_SERVICE_INTEGRATION_PLAN.md).
> Сервис не является антивирусом или полным penetration-testing продуктом; отчёты показывают покрытие и ограничения проверок.

---

## 0. Ключевые решения (ADR)

| # | Решение | Обоснование |
|---|---|---|
| ADR-1 | Только **статический** разбор. Никогда не загружать PE в память как образ и не исполнять | Загружаемый файл — недоверенный, потенциально malware |
| ADR-2 | Парсить файл **один раз** в immutable-агрегат `PeImage` (сейчас `PeAnalysisModule` открывает файл 3 раза: header → section → imports) | Скорость + консистентность снимка данных |
| ADR-3 | Правила — **C#-классы `IRule`**, а данные (пороги, списки API, имена секций) — **JSON-каталоги** | Логика типизирована и тестируема, данные меняются без кода |
| ADR-4 | Агрегация риска — **в `Core`**, не в `Server` | Переиспользование в Console, тестах, будущем CLI |
| ADR-5 | ZIP: **безопасная распаковка в temp с жёсткими лимитами** (v1), стриминг-парсинг без распаковки — v2 | Минимальные изменения парсеров, но лимиты обязательны |
| ADR-6 | Authenticode через **`SignedCms` + `X509Chain`** (кроссплатформенно); `WinVerifyTrust` — опционально только на Windows | Server может работать в Linux-контейнере |
| ADR-7 | Server — **Minimal API** (соответствует текущему шаблону), OpenAPI через встроенный `Microsoft.AspNetCore.OpenApi` | Не тянуть лишние зависимости |
| ADR-8 | UI — **React 19 + TS без новых runtime-зависимостей** (только `openapi-typescript` как dev-dep, опционально) | Держим проект лёгким |
| ADR-9 | Общий риск = **max по файлам** + счётчики, но с явным детерминированным алгоритмом (раздел 5) | Простота и воспроизводимость |

---

## 1. Аудит текущего состояния (план v1 vs код)

| Пункт плана v1 | Факт | Действие |
|---|---|---|
| 1.1 «расширить mitigations» — не сделано | `HeaderParser.cs:104-113` уже парсит ASLR, DEP, HighEntropyVA, CFG | Отметить как частично done; добавить SafeSEH, Authenticode, Checksum, EntryPoint, Subsystem |
| 1.2 Entropy | отсутствует | Реализовать |
| 1.3 ImportedParser — done | `Core/ImpParser/ImportedParser.cs` работает | Использовать как основу, переписать на `Stream`, добавить delay-load |
| 1.4 RiskyApiScanner | отсутствует | Реализовать как `IRule` + JSON-каталог |
| 1.5 RiskAssessmentEngine | отсутствует | Реализовать в `Core/Risk` |
| 2.1 «добавить ссылку на Core» | `Server.csproj:10` уже ссылается | Отметить done |
| 2.x API/ZIP | отсутствует, `Server/Program.cs` — шаблон `weatherforecast` | Удалить шаблон, реализовать |
| 3.x UI | `UI/src/App.tsx` — дефолтный Vite-шаблон | Переписать |
| Тесты `Core.Tests` | есть `Test/Test.csproj`; **`Test/ParseHeaderTest.cs:44` падает** (ждёт `"Wrong signature"`, парсер возвращает `"The PE signature is invalid."` из `ParseHeader.cs:47`) | Починить, перевести на синтетические PE-фикстуры вместо `C:\Windows\...` |
| CI | `.github/workflows` пуста | Добавить workflow |
| Инфраструктура модулей | уже есть `IScanModule`/`ScanCoordinator` (`Core/Scanning/ScanCoordinator.cs:4`) и модель findings (`Core/Scanning/ScanModels.cs:34-78`) | Всё новое встраивать **в эту модель**, не создавать параллельную |

**Вывод:** план v1 устарел по статусам и вводит второй понятийный аппарат (`SecurityRuleEngine` рядом с `ScanFinding`). v2 устраняет это.

---

## 2. Целевая архитектура

```
┌──────────────────────────── UI (React/TS) ────────────────────────────┐
│ UploadZone · RiskBanner · FileTree · Findings · Mitigations · Entropy │
└───────────────────────────────┬───────────────────────────────────────┘
                                │ REST (multipart, JSON)
┌────────────────────────── Server (ASP.NET Core) ──────────────────────┐
│ Endpoints/ScanEndpoints  Services/FileScanService  Services/ArchiveService │
│ Options/ScannerOptions   Middleware/ExceptionHandling  RateLimiter    │
└───────────────────────────────┬───────────────────────────────────────┘
                                │ ScanCoordinator + IScanModule[]
┌──────────────────────────── Core (.NET) ──────────────────────────────┐
│ Analysis: PeImageParser → PeImage (single-open aggregate)             │
│ Parsers: Header · Section · Import · DelayImport · LoadConfig · Cert  │
│ Analysis: EntropyScanner · OverlayScanner · SignatureVerifier         │
│ Rules: IRule · RuleEngine · BuiltIn/* · catalogs (JSON)               │
│ Risk: RiskAssessmentEngine · RiskLevel · RiskScore                    │
│ Scanning: PeScanModule (IScanModule) · ScanCoordinator (existing)     │
└───────────────────────────────────────────────────────────────────────┘
```

Поток скана одного файла:
`PeScanModule.ScanAsync` → `PeImageParser.Parse` (1 открытие файла) → `RuleEngine.Evaluate(context)` → `ScanFinding[]` → `RiskAssessmentEngine.Assess` → `ScanModuleResult` (findings + artifacts + risk в артефакте `risk.summary`).

Архив: `ArchiveService` безопасно извлекает → список PE → `Parallel.ForEachAsync` (bounded) → по каждому `ScanCoordinator.ScanAsync` → агрегация в `ArchiveScanResponse`.

---

## 3. Модель данных (в `Core`)

Новое/изменяемое:

```csharp
// Core/Analysis/PeImage.cs
public sealed record PeImage(
    string Path,
    long FileSize,
    HPInfo Header,                       // расширенный
    IReadOnlyList<SingleSectionInfo> Sections,
    IReadOnlyList<SectionEntropy> Entropy,
    ImportParseResult Imports,
    IReadOnlyList<ImportedDLL> DelayImports,
    LoadConfigInfo? LoadConfig,
    CertificateInfo Signature,
    OverlayInfo Overlay);

// Core/Models/HeaderParser/HPInfo.cs — добавить:
// Subsystem, AddressOfEntryPoint, TimeDateStamp, CheckSum, SizeOfImage,
// ResourceDirectory(Rva/Size), SecurityDirectory(FileOffset/Size),
// LoadConfigDirectory, DelayImportDirectory, ExportDirectory, DebugDirectory,
// IsDll (Characteristics & IMAGE_FILE_DLL)

// Core/Analysis/SectionEntropy.cs
public sealed record SectionEntropy(string Name, double Entropy, uint RawSize, bool IsExecutable, bool IsResource);
```

`ScanModels.cs` **не ломаем**: `ScanFinding`, `ScanSeverity`, `ScanReport` остаются контрактом. Добавляем только:

```csharp
// Core/Risk/RiskModels.cs
public enum RiskLevel { Info, Low, Medium, High, Critical }
public sealed record RiskScore(RiskLevel Level, int Score,
    IReadOnlyDictionary<ScanSeverity,int> Counts);
public static class RiskReportExtensions { /* ReportRisk(this ScanReport) */ }
```

---

## 4. Движок правил и каталог

```csharp
// Core/Rules/IRule.cs
public interface IRule {
    string Id { get; }
    string Category { get; }
    IEnumerable<ScanFinding> Evaluate(RuleContext context);
}
public sealed record RuleContext(PeImage Image, RuleOptions Options);
```

Данные (embedded JSON или `Core/Rules/catalogs/*.json`): `risky-apis.json` (группы API + severity), `section-names.json`, `thresholds.json` (энтропия, overlay, размеры).

### 4.1 Каталог правил (стартовый набор)

**Mitigations**

| ID | Условие | Severity |
|---|---|---|
| PE-MIT-001 | нет ASLR (`DynamicBase`) | High (EXE) / Medium (DLL) |
| PE-MIT-002 | нет DEP (`NX_COMPAT`) | High (EXE) / Medium (DLL) |
| PE-MIT-003 | нет CFG (`GuardCF`) | Low |
| PE-MIT-004 | x86, нет SafeSEH (нет `SEHandlerTable/Count` в LoadConfig), но есть SEH | Medium |
| PE-MIT-005 | x64 и нет `HighEntropyVA` | Low |
| PE-MIT-006 | CFG-флаг есть, но `GuardFlags` не содержит `CF_INSTRUMENTED` | Info (несоответствие) |

**Sections / Layout**

| ID | Условие | Severity |
|---|---|---|
| PE-SEC-001 | секция `MemWrite && MemExecute` | **Critical** |
| PE-SEC-002 | entry point в writable или не в executable секции | High |
| PE-SEC-003 | entry point вне всех секций / за EOF | High |
| PE-SEC-004 | подозрительные имена (`UPX0/UPX1`, `.packed`, `.aspack`, `.themida`, `.vmp`) | High |
| PE-SEC-005 | энтропия executable-секции > 7.2 (без `.rsrc`) | High |
| PE-SEC-006 | энтропия executable-секции 6.8–7.2 | Medium |
| PE-SEC-007 | пересекающиеся raw-диапазоны секций | Medium |
| PE-SEC-008 | raw-данные секции выходят за EOF | High |
| PE-SEC-009 | секция execute с `SizeOfRawData == 0` | Medium |
| PE-SEC-010 | overlay > 5% и > 64 KB (хвост после последней секции) | Low |
| PE-SEC-011 | нетипичные символы в имени секции | Low |

**Imports**

| ID | Условие | Severity |
|---|---|---|
| PE-IMP-001 | ≥3 из injection-набора (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`) | **Critical** |
| PE-IMP-002 | 1–2 injection-примитива | High/Medium |
| PE-IMP-003 | networking/download (`InternetOpen`, `URLDownloadToFile`, `WinHttp*`, `WSAStartup`) | Medium |
| PE-IMP-004 | persistence (`RegSetValueEx`, `CreateService`, `OpenSCManager`) | Medium |
| PE-IMP-005 | anti-debug (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`) | Low/Medium |
| PE-IMP-006 | dynamic resolution (`LoadLibrary`+`GetProcAddress`) | Medium |
| PE-IMP-007 | crypto (`CryptEncrypt`, `BCryptEncrypt`) | Info |
| PE-IMP-008 | импорты только по ординалам | Low |
| PE-IMP-009 | опасный API только в delay-load секции | Info |
| PE-IMP-010 | нет импортов вообще | High (упаковано/подозрительно) |

**Header / Signature**

| ID | Условие | Severity |
|---|---|---|
| PE-HDR-001 | нестандартная подсистема (native/EFI) | Medium |
| PE-HDR-002 | `TimeDateStamp == 0` или в будущем | Low |
| PE-HDR-003 | невалидная PE-контрольная сумма | Low |
| PE-SIG-001 | подпись есть, но невалидна (CMS) | High |
| PE-SIG-002 | подпись есть, цепочка не доверена/просрочена | Low |
| PE-SIG-003 | подписи нет | Low (настраивается) |

Нормализация API: сравнение без учёта регистра, суффиксы `A`/`W` схлопываются, `#ordinal` учитывается отдельно.

---

## 5. Алгоритм оценки риска (детерминированный)

Веса: `Critical=50, High=15, Medium=5, Low=1, Info=0`.

```
score = Σ weight(finding.severity)
if any Critical                       -> Critical
else if score >= 15 or HighCount >= 2 -> High
else if score >= 5  or MediumCount>=1 -> Medium
else if score >= 1  or LowCount  >= 1 -> Low
else                                  -> Info
```

- Уровень файла считается по его findings.
- Уровень архива = **max(уровень файлов)**; счётчики суммируются; `score` архива — сумма, но в UI показывается max-уровень.
- Severity конкретного правила может зависеть от `IsDll`, архитектуры и контекста (см. таблицы).
- Все пороги — в `thresholds.json`, чтобы калибровать без пересборки.

---

## 6. Безопасность (обязательные требования)

### 6.1 Загрузка

- Лимиты (appsettings, секция `Scanner`): `MaxFileBytes=100MB`, `MaxArchiveBytes=200MB`, `MaxUncompressedBytes=1GB`, `MaxEntries=500`, `MaxCompressionRatio=100`, `MaxEntryBytes=100MB`, `MaxScanSeconds=120`.
- Проверять **magic** (`MZ` → `PE\0\0`), а не расширение/MIME. Расширение — только для UX.
- Отклонять зашифрованные ZIP-записи, symlink/hardlink (external attributes), дубликаты имён, `..`/абсолютные пути, слишком длинные пути.

### 6.2 ZIP (Zip Slip / bomb)

- Свой extractor на `System.IO.Compression.ZipArchive`, **никогда** `ExtractToDirectory`.
- Для каждой записи: `full = Path.GetFullPath(Path.Combine(dest, entry.FullName))` → `full.StartsWith(destCanonical + sep)` иначе reject.
- Стриминговая копия с подсчётом байт и проверкой ratio; при превышении — abort.
- Вложенные ZIP — не распаковывать (v1), помечать как `unsupported`.
- Temp-каталог: уникальный `Path.Combine(Path.GetTempPath(), "scanner", scanId)`; удаление в `try/finally` + фоновая очистка старше 1 часа.

### 6.3 Ресурсы

- `Parallel.ForEachAsync` с `MaxDegreeOfParallelism = min(ProcessorCount, 4)`.
- Общий `CancellationTokenSource` + `CancelAfter(MaxScanSeconds)`; таймаут на файл.
- Парсеры — stateless singleton; каждый вызов открывает свой `FileStream` (уже так).
- Все чтения — только в пределах файла (уже реализовано в `HeaderParser.IsRangeWithinFile`, `RVAConverter`).

### 6.4 Прочее

- Rate limiting на `/api/scan/*`.
- Никаких секретов в репозитории; лимиты — конфиг/переменные окружения.
- Логи: не писать содержимое файлов и PII; только имена, размеры, ruleId.
- Явный комментарий в README: сервис не является антивирусом.

---

## 7. REST API (контракт)

```
POST /api/scan/file      multipart/form-data: file
POST /api/scan/archive   multipart/form-data: file (.zip)
GET  /api/scan/health    (liveness)
```

Коды: `200` успех (даже если отдельные файлы failed), `400` invalid, `413` too large, `415` unsupported type, `429` rate limit, `500` unexpected.

```jsonc
// ScanFileResponse
{
  "scanId": "guid",
  "fileName": "app.exe",
  "fileSize": 123456,
  "status": "Succeeded|PartiallySucceeded|Failed|Unsupported",
  "risk": { "level": "High", "score": 21,
            "counts": { "critical": 0, "high": 1, "medium": 1, "low": 2, "info": 3 } },
  "findings": [ { "ruleId": "PE-MIT-001", "title": "...", "category": "Mitigations",
                  "severity": "High", "description": "...", "evidence": "...",
                  "recommendation": "...", "standardReference": "CWE-693" } ],
  "artifacts": {
    "header": { "architecture": "x64", "subsystem": "GUI", "entryPoint": "0x..." },
    "sections": [ { "name": ".text", "entropy": 6.41, "executable": true, "writable": false } ],
    "imports": [ { "dll": "KERNEL32.dll", "functions": [ "VirtualAlloc" ] } ],
    "mitigations": { "aslr": true, "dep": true, "cfg": false, "safeSeh": "N/A", "highEntropyVa": true },
    "signature": { "state": "Unsigned|Valid|Invalid|Untrusted|Expired" },
    "overlay": { "size": 0, "entropy": 0.0 }
  },
  "errors": []
}

// ArchiveScanResponse
{
  "scanId": "guid", "archiveName": "bundle.zip",
  "overallRisk": { "level": "Critical", "score": 50,
                   "counts": { "critical": 2, "high": 3, "medium": 5, "low": 1, "info": 4 } },
  "files": [ /* ScanFileResponse[] с relativePath */ ],
  "errors": [ { "path": "x/y.exe", "message": "unsupported" } ]
}
```

- DTO — в `Server/DTOs`, маппинг из `ScanReport` — extension-методы.
- OpenAPI включить; TS-типы — либо вручную, либо `openapi-typescript` (dev).

---

## 8. UI (структура и поведение)

```
src/
  api/client.ts, types.ts
  hooks/useScan.ts             // upload, loading, error, abort
  components/UploadZone.tsx    // drag&drop, .exe/.dll/.sys/.zip, валидация размера
  components/RiskBanner.tsx    // цвет + level + counts
  components/FileTree.tsx      // список файлов архива, выбор, статус
  components/FindingsList.tsx  // фильтр по severity, сортировка, ссылки
  components/SeverityFilter.tsx
  components/Mitigations.tsx   // ASLR/DEP/CFG/SafeSEH/HEVA + signature
  components/EntropyBars.tsx   // полосы по секциям, threshold-линия
  components/ImportedApis.tsx  // таблица, подсветка flagged
  components/FileReportView.tsx// вкладки: Findings | Mitigations | Sections | Imports
  App.tsx
```

Требования: состояния `idle/uploading/scanning/success/error`, отображение лимитов и ошибок (`413/415/429`), `AbortController`, доступность (roles, aria-live для баннера), без новых runtime-зависимостей. Для сотен файлов — простая виртуализация списка или пагинация (без библиотек — ок).

---

## 9. Фазы, задачи, DoD, оценка

### Phase 0 — Baseline & hygiene (0.5–1 день)

- [ ] Починить `Test/ParseHeaderTest.cs` (ожидаемое сообщение) и убрать зависимость от `C:\Windows\...`.
- [ ] `Directory.Build.props` (nullable, warnings), `.editorconfig`.
- [ ] CI: `dotnet restore/build/test` (ubuntu + windows), `npm ci && npm run build && npm run lint`.
- [ ] README: scope, «не антивирус», лимиты.

**DoD:** чистый клон → CI зелёный, `dotnet test` проходит на Linux и Windows.

### Phase 1 — Core: парсинг и агрегат (2–3 дня)

- [ ] `Core/Analysis/PeImageParser.cs` — один `FileStream` на файл.
- [ ] Расширить `HPInfo` (Subsystem, EntryPoint, Timestamp, Checksum, Data Directories, IsDll).
- [ ] `LoadConfigParser` (SafeSEH, GuardFlags) — только x86 для SafeSEH.
- [ ] `DelayImportParser` (directory index 13).
- [ ] `OverlayScanner`, `EntropyScanner`.
- [ ] `CertificateParser` + `SignatureVerifier` (`SignedCms`, `X509Chain`, статусы).
- [ ] Переписать `ImportedParser` на `Stream`+offset (без повторного открытия).

**DoD:** unit-тесты на синтетических PE (валидные/битые), нет unhandled exceptions на корпусе malformed-файлов, все парсеры покрыты bounds-проверками.

### Phase 2 — Rules + Risk (2–3 дня)

- [ ] `IRule`, `RuleEngine`, `RuleContext`, `RuleOptions`.
- [ ] JSON-каталоги: risky-apis, section-names, thresholds.
- [ ] 25–30 правил из раздела 4.1.
- [ ] `RiskAssessmentEngine` по алгоритму раздела 5.
- [ ] `PeScanModule` вместо логики в `PeAnalysisModule`; Console печатает findings + risk.

**DoD:** правила покрыты тестами (по одному кейсу на правило), Console показывает корректный риск на 3–5 эталонных файлах.

### Phase 3 — Server API + ZIP (2–3 дня)

- [ ] Удалить `weatherforecast`; DI (парсеры, каталоги, engine, модули, coordinator).
- [ ] `ScannerOptions` из конфига + валидация.
- [ ] `TempStorage` (безопасная распаковка, cleanup), `FileScanService`, `ArchiveService`.
- [ ] `ScanEndpoints` (file/archive/health), лимиты, rate limiter, error middleware.
- [ ] OpenAPI + DTO + маппинг.
- [ ] Integration-тесты (`WebApplicationFactory`): valid exe, zip, zip-slip, bomb, too-large, bad magic.

**DoD:** `POST /api/scan/file` и `/api/scan/archive` работают по контракту; все security-лимиты проверяются тестами.

### Phase 4 — UI (3–4 дня)

- [ ] `api/client.ts`, `useScan`.
- [ ] Upload/Banner/Tree/Findings/Mitigations/Entropy/Imports.
- [ ] Обработка ошибок и лимитов, loading/abort.

**DoD:** `npm run build`, `npm run lint` без ошибок; ручной e2e на наборе: benign exe, UPX-подобный, zip с несколькими PE, битый zip.

### Phase 5 — Polish (1–2 дня, опционально)

- [ ] Прогресс/SSE для больших архивов, история сканов (in-memory, без БД), экспорт JSON-отчёта, базовый i18n не нужен.

**Итого: ~10–14 человеко-дней.**

---

## 10. Тестирование и качество

- **Unit (`Test`)** — синтетические байтовые PE через `PeBuilder`-хелпер; никаких системных путей (CI на Linux).
- **Парсеры** — позитив/негатив: truncated, bad magic, RVA overflow, huge section count, loop в импортах, отсутствие null-terminator.
- **Entropy** — нули = 0, равномерный random ≈ 8, пороги.
- **Правила** — по кейсу на правило; combo-правила (injection triad).
- **ZIP** — zip-slip, bomb, > entries, encrypted, symlink, nested.
- **Integration** — `WebApplicationFactory` на всё API.
- **Signature** — тесты CMS на кросс-платформе; `WinVerifyTrust`-кейсы только `[Trait("Platform","Windows")]` и скип на Linux.
- CI: matrix ubuntu/windows; `dotnet format --verify-no-changes` (опционально).

---

## 11. Риски и меры

| Риск | Мера |
|---|---|
| Malware на сервере | parse-only, temp-изоляция, cleanup, никакого exec, README-disclaimer |
| Zip bomb / DoS | лимиты размера/ratio/entries, bounded parallelism, таймауты |
| Zip Slip | canonical-path проверка, отказ от `ExtractToDirectory` |
| Ложные срабатывания энтропии | исключать `.rsrc`/`.reloc`, настраиваемые пороги, severity-градация |
| Authenticode на Linux | `SignedCms`+`X509Chain`, явные статусы, документированные ограничения |
| net10.0 tooling | зафиксировать SDK в CI (`setup-dotnet`), проверить `xunit`/`vite` совместимость |
| Устаревание плана | статусы и DoD поддерживать в этом файле; PR-чеклист по фазам |

---

## 12. Вне scope (v1)

Динамический анализ/эмуляция, sandbox, YARA, VirusTotal, распаковка/деобфускация, БД и история, аутентификация/мультиюзер, CI-интеграция как сервис.

---

## 13. Принятые решения по умолчанию

1. **Платформа Server:** кроссплатформенно (Linux-контейнер); `WinVerifyTrust` не используем в v1.
2. **Рефакторинг `Core` на single-open `PeImage`** — да, внутренние сигнатуры парсеров меняются.
3. **Authenticode:** `SignedCms` + `X509Chain` без `WinVerifyTrust`.
4. **Скан архива:** синхронный запрос с таймаутом 120с; SSE/джобы — Phase 5.
5. **UI:** функциональный MVP без новых runtime-зависимостей.
6. **Тестовый проект:** оставить папку `Test`, починить/переименовать namespace на `Core.Tests`.

---

## 14. Что будет изменено/создано

**Изменено:** `Core/PE/ParseHeader.cs`, `Core/Models/HeaderParser/HPInfo.cs`, `Core/ImpParser/ImportedParser.cs`, `Core/PE/PeAnalysisModule.cs`, `Core/Scanning/ScanModels.cs` (только аддитивно), `Scanner.Console/Program.cs`, `Server/Program.cs`, `Server/Server.csproj`, `Test/*`, `UI/src/*`, `.github/workflows/ci.yml`.

**Создано:** `Core/Analysis/*`, `Core/Parsing/LoadConfigParser.cs`, `Core/Parsing/DelayImportParser.cs`, `Core/Security/*`, `Core/Rules/*`, `Core/Risk/*`, `Core/Analysis/EntropyScanner.cs`, `Server/Endpoints/*`, `Server/Services/*`, `Server/Options/*`, `Server/DTOs/*`, `Server/Middleware/*`, `Server.Tests/*`, `UI/src/api/*`, `UI/src/hooks/*`, `UI/src/components/*`.

---

## 15. Верификация (актуальная)

1. **Unit (`Test`)** — парсеры, энтропия, правила, риск, безопасная распаковка ZIP.
2. **Integration (`Server.Tests`)** — end-to-end `/api/scan/file` и `/api/scan/archive`, проверка лимитов и Zip Slip.
3. **Frontend** — `npm run build` и `npm run lint` в `UI/` без TypeScript/CSS ошибок.
4. **CI** — matrix ubuntu/windows, `dotnet test` + frontend build/lint.
