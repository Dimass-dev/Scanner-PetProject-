# Scanner Desktop - Windows Application

Windows Desktop приложение для Security Scanner с современным UI интерфейсом.

## Возможности

- 🖱️ **Drag & Drop**: Перетаскивание файлов для быстрого сканирования
- 📄 **PE File Scanner**: Сканирование исполняемых файлов (.exe, .dll, .sys)
- 📦 **Archive Scanner**: Анализ ZIP архивов с несколькими файлами
- 📊 **Подробные результаты**: Визуализация рисков, находок и security mitigations
- 📜 **История сканирований**: Отслеживание всех предыдущих сканирований
- 🎨 **Современный UI**: Material Design стиль с цветовой индикацией рисков

## Требования

- Windows 10/11
- .NET 10 SDK или runtime
- Scanner Server API должен быть запущен на `http://localhost:5290`

## Установка и запуск

### 1. Запуск Scanner Server

Перед запуском Desktop приложения необходимо запустить Server API:

```bash
cd Scanner(PetProject)
dotnet run --project Server/Server.csproj --launch-profile http
```

Server будет доступен на `http://localhost:5290`

### 2. Запуск Desktop приложения

```bash
cd Scanner(PetProject)/Scanner.Desktop
dotnet run
```

Или соберите exe файл:

```bash
dotnet publish -c Release -r win-x64 --self-contained
```

Исполняемый файл будет находиться в `bin\Release\net10.0-windows\win-x64\publish\`

## Использование

### Сканирование PE файлов

1. Откройте вкладку **📄 PE File Scanner**
2. Перетащите файл в зону drop или нажмите **Browse Files**
3. Выберите .exe, .dll или .sys файл
4. Результаты появятся справа с детальной информацией:
   - Risk Level (цветовая индикация)
   - Security Mitigations (ASLR, DEP, CFG, etc.)
   - Findings с категориями severity
   - Total Score

### Сканирование архивов

1. Откройте вкладку **📦 Archive Scanner**
2. Перетащите .zip файл в зону drop или нажмите **Browse Archives**
3. Просмотрите результаты для каждого файла в архиве
4. Разверните файлы для детальной информации

### История сканирований

Вкладка **📜 History** показывает все выполненные сканирования в текущей сессии.

## Архитектура

Проект использует современные подходы разработки WPF приложений:

- **MVVM Pattern**: Разделение логики и представления
- **CommunityToolkit.Mvvm**: Упрощение MVVM с генераторами кода
- **Dependency Injection**: Microsoft.Extensions.DependencyInjection
- **HttpClient**: Асинхронное взаимодействие с REST API
- **Material Design**: Современный UI с цветовыми индикаторами

### Структура проекта

```
Scanner.Desktop/
├── Models/              # Модели данных (ScanResult, Finding, etc.)
├── ViewModels/          # ViewModels с бизнес-логикой (MainViewModel)
├── Views/               # XAML представления
├── Services/            # API клиенты (ScannerApiClient)
├── Converters/          # Value converters для XAML binding
└── Resources/           # Ресурсы (иконки, стили)
```

## Цветовая схема рисков

- 🔴 **CRITICAL** - Критические уязвимости (50+ pts)
- 🟠 **HIGH** - Высокий риск (15+ pts)
- 🟡 **MEDIUM** - Средний риск (5+ pts)
- 🟢 **LOW** - Низкий риск (1+ pts)
- 🔵 **INFO** - Информационные находки

## Конфигурация

API endpoint настроен в `ScannerApiClient.cs`:

```csharp
_httpClient.BaseAddress = new Uri("http://localhost:5290");
```

Для изменения адреса сервера отредактируйте этот параметр.

## Troubleshooting

### Приложение не подключается к серверу

1. Проверьте, что Server запущен: `http://localhost:5290/api/scan/health`
2. Убедитесь, что firewall не блокирует порт 5290
3. Нажмите кнопку **🔄 Refresh** для повторной проверки соединения

### Ошибки при сканировании

- Убедитесь, что размер файла не превышает 100 MB (для single files) или 200 MB (для archives)
- Проверьте, что формат файла поддерживается (.exe, .dll, .sys, .zip)

## Технологии

- .NET 10
- WPF (Windows Presentation Foundation)
- CommunityToolkit.Mvvm 8.4.2
- Microsoft.Extensions.Http 10.0.14
- Microsoft.Extensions.DependencyInjection 10.0.14

## Лицензия

MIT License - см. LICENSE файл в корне проекта.
