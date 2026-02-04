# Команды для запуска тестов

## Базовые тесты

### Одиночный PING тест
```bash
cargo run -- --test-ping
```

### Множественные PING пакеты (например, 10)
```bash
cargo run -- --multiple-pings 10
```

### Интеграционный тест (полный цикл клиента)
```bash
cargo run -- --integration
```

### Все тесты
```bash
cargo run -- --all-tests
```

## Стресс-тесты

### Быстрый стресс-тест
```bash
cargo run -- --stress
```

### Очень быстрый стресс-тест
```bash
cargo run -- --stress-quick
```

### Интенсивный стресс-тест
```bash
cargo run -- --stress-intensive
```

### Тест стабильности
```bash
cargo run -- --stability
```

## Кастомный стресс-тест

Формат: `КЛИЕНТЫ:ПАРАЛЛЕЛЬНЫЕ:ПАКЕТОВ:ЗАДЕРЖКА_МС`

### Пример 1: Умеренная нагрузка
```bash
cargo run -- --stress-config "50:10:5:100"
```

### Пример 2: Высокая нагрузка
```bash
cargo run -- --stress-config "100:20:10:50"
```

### Пример 3: Экстремальная нагрузка
```bash
cargo run -- --stress-config "200:50:20:30"
```

## Простой клиент (без тестов)
```bash
cargo run
```