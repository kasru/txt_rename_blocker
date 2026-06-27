# File Rename Blocker Module (Linux 6.12)

## Описание

Модуль ядра для перехвата операций переименования файлов с расширением .txt.
Блокирует переименование файлов, первые 16 байт которых совпадают с настроенным значением.

## Требования

- Linux Kernel 6.12 (RedOS 8)
- Заголовочные файлы ядра (linux-headers)
- GCC компилятор
- Make

## Установка

### 1. Установка зависимостей
```bash
sudo dnf install gcc make kernel-devel
```

## 2. Сборка

```bash
make
```

## Использование

### 1. Создать конфиг (16 байт)
```bash
echo -n "PROTECTED_HEADER" | sudo tee /etc/txt_rename_blocker.cfg
```

### 2. Загрузить модуль
```bash
sudo insmod txt_rename_blocker.ko
```

### 3. Проверить работу
```bash
# Создать защищённый файл
echo -n "PROTECTED_HEADER secret" > /tmp/test.txt

# Попытка rename
mv /tmp/test.txt /tmp/renamed.txt

# Проверить лог
sudo dmesg | tail
```

### 3. Выгрузить модуль
```bash
sudo rmmod txt_rename_blocker
```

## Особенности реализации

- Конфиг читается однократно при загрузке модуля; для смены заголовка нужно перезагрузить модуль.
- При отсутствии конфига модуль загружается, но блокировка не производится.

## Технические детали

- Реализована версия модуля с ftrace + override_function_with_return, rename блокируется с -EPERM (errno 1)
- kallsyms_lookup_name найден через kprobe, вызван как функция; затем через него найден override_function_with_return
- override_function_with_return успешно вызывается после установки regs->ax = -EPERM, заставляя do_renameat2 немедленно вернуться с EPERM
- Конфигурационный файл /etc/txt_rename_blocker.cfg читается на этапе инициализации модуля через filp_open + kernel_read
- В ftrace-обработчике файл .txt открывается через filp_open, читаются первые 16 байт (kernel_read), сравниваются с защищаемым заголовком; при совпадении — блокировка с EPERM
- Относительные пути корректно обрабатываются: filp_open внутри ftrace-хука использует current->fs->pwd (CWD процесса)
- Добавлена проверка preemptible() перед вызовом filp_open — если контекст атомарный, проверка заголовка пропускается (rename разрешается)
- Для проверки содержимого файла применён filp_open + kernel_read прямо из ftrace-обработчика; если контекст прерываем используем preemptible(), поэтому вызовы VFS безопасны

### Как это работает
1. ftrace на do_renameat2 — перехват на входе функции
2. kallsyms_lookup_name найден через kprobe, вызван как функция чтобы найти адрес override_function_with_return
3. В хендлере для .txt: regs->ax = -EPERM + override_function_with_return(regs) — мгновенный возврат с EPERM, rename не выполняется
4. Для не .txt: хендлер ничего не делает, rename проходит нормально
