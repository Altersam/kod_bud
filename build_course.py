#!/usr/bin/env python3
"""Build a cohesive, self-contained Cybersecurity / Python course.

Usage: python build_course.py --root . --strict
This file is safe to rerun: only blocks marked KD_* are replaced.
All HTML pages stay in the root. AI_*.html are never read or modified.
"""
from __future__ import annotations
import argparse, ast, html, json, os, re, shutil, textwrap
from pathlib import Path
from urllib.parse import urlparse

SITE = 'https://altersam.github.io/kod_bud/'
RESOURCE = {
 'py':'https://docs.python.org/3/',
 'owasp':'https://cheatsheetseries.owasp.org/',
 'nists':'https://csrc.nist.gov/publications/sp800',
}

def topic(n, title, module, summary, asset, threat, signal, control, verify, goals, story, explanation, code, expected, quiz, options, correct, rationale, references, tag):
 return dict(n=n, title=title, module=module, summary=summary, asset=asset, threat=threat,
             signal=signal, control=control, verify=verify, goals=goals, story=story,
             explanation=explanation, code=textwrap.dedent(code).strip()+'\n', expected=expected,
             quiz=quiz, options=options, correct=correct, rationale=rationale,
             references=references, tag=tag, path=('PA_1.html' if n == 15 else f'lesson_{n}.html'))

LESSONS = [
 topic(1,'Введение в кибербезопасность','Основы защиты',
 'CIA, угрозы, STRIDE и первые строки Python: учимся смотреть на систему глазами защитника.',
 'Учётные записи и данные', 'Несанкционированный вход','Неудачные попытки входа',
 'Модель угроз и журналирование','Назвать актив, угрозу и способ проверки',
 ['Различать конфиденциальность, целостность и доступность', 'Строить простую цепочку «угроза → защита»','Читать события журнала на Python'],
 'В школьном портале «Сигнал» кто-то несколько раз вводит неверный пароль. Один сбой — не доказательство атаки, но серия событий требует анализа.',
 'Модель угроз начинается с актива: что именно нужно защитить? Триада CIA задаёт три критерия. Журнал событий — наблюдаемое подтверждение активности, но по одному признаку нельзя уверенно приписывать человеку злонамеренные действия.',
 '''
    logs = ["LOGIN_FAIL", "LOGIN_OK", "LOGIN_FAIL", "LOGIN_FAIL"]
    failures = sum(event == "LOGIN_FAIL" for event in logs)
    print("Неудачных попыток:", failures)
    print("Нужен анализ" if failures >= 3 else "Продолжаем наблюдение")
 ''', 'Неудачных попыток: 3\\nНужен анализ',
 'Почему три ошибки входа ещё не доказывают атаку?',
 ['Потому что журнал всегда ошибается','Потому что возможны опечатки и технические сбои','Потому что пароли не нужны'],1,
 'События дают сигнал, но не объясняют намерения. Важно учитывать контекст, время, устройство и дополнительные признаки.',
 [('NIST Cybersecurity Framework','https://www.nist.gov/cyberframework'),('OWASP: Logging Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html')], 'Карта угроз'),
 topic(2,'Право, этика и персональные данные','Основы защиты',
 'Безопасность начинается с законной цели, минимизации данных и уважения прав человека.',
 'Профили пользователей','Избыточный сбор данных','Лишние поля в анкете',
 'Минимизация и разграничение доступа','Обосновать каждое хранимое поле',
 ['Отличать персональные данные от обезличенных', 'Понимать принципы законной обработки','Проектировать форму без лишних сведений'],
 'Команда разрабатывает форму регистрации: ей предлагают добавить дату рождения, адрес и номер паспорта «на всякий случай».',
 'Если функциональности достаточно имени пользователя и адреса для связи, дополнительные поля повышают риск утечки. Маскировка строки не делает данные анонимными: исходная запись может оставаться идентифицируемой.',
 '''
    # Учебный пример минимизации отображаемых данных.
    profile = {"login": "student7", "email": "student7@example.org", "address": "лишнее поле"}
    public = {key: profile[key] for key in ("login",)}
    print(public)
 ''', "{'login': 'student7'}",
 'Что важнее всего при проектировании формы регистрации?',
 ['Собирать все доступные сведения','Хранить данные в открытом виде','Обрабатывать только необходимое для конкретной цели'],2,
 'Минимизация снижает последствия возможной утечки. Основание обработки и сроки хранения оцениваются отдельно.',
 [('Роскомнадзор','https://rkn.gov.ru/'),('EDPB: Data protection basics','https://www.edpb.europa.eu/'),('OWASP: Privacy Risks','https://owasp.org/www-project-top-10-privacy-risks/')], 'Цифровая этика'),
 topic(3,'Безопасная среда разработки','Разработка и анализ',
 'venv, Git, .gitignore, секреты и переменные окружения для воспроизводимой разработки.',
 'Исходный код и токены','Секрет попал в Git','Ключ в истории коммитов',
 'Переменные окружения и контроль репозитория','Проверить отсутствие секретов в истории',
 ['Объяснять назначение venv и .env', 'Не записывать реальные ключи в исходники','Проверять изменения перед коммитом'],
 'Перед публикацией учебного проекта в публичный репозиторий проверяем: не попали ли туда пароли, токены и локальные настройки.',
 'Файл .env сам по себе не обеспечивает безопасность. Нельзя коммитить файл с реальными секретами. Если токен уже опубликован, удалить файл недостаточно: ключ нужно отозвать и заменить.',
 '''
    import os
    token = os.getenv("SIGNAL_API_TOKEN")
    if token:
        print("Конфигурация найдена; значение не показываем")
    else:
        print("Настройте переменную окружения SIGNAL_API_TOKEN")
 ''', 'Настройте переменную окружения SIGNAL_API_TOKEN (если переменная не задана)',
 'Токен случайно оказался в Git. Какое действие обязательно?',
 ['Отозвать и заменить токен','Только удалить строку в новой версии файла','Переименовать файл'],0,
 'История Git может сохранять удалённое из текущей версии содержимое. Секреты требуют ротации.',
 [('Python: venv','https://docs.python.org/3/library/venv.html'),('Git: .gitignore','https://git-scm.com/docs/gitignore'),('OWASP: Secrets Management','https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html')], 'Защита кода'),
 topic(4,'Типы, условия и циклы Python','Разработка и анализ',
 'Базовые конструкции Python используются для безопасной обработки неидеального пользовательского ввода.',
 'Входные параметры','Некорректный ввод','Ошибка типа или диапазона',
 'Валидация до выполнения действия','Проверить граничные значения',
 ['Использовать int, bool, str по назначению','Отличать while от if','Обрабатывать неверный ввод без падения'],
 'Система мониторинга спрашивает, сколько последних событий показать. Неограниченное значение может перегрузить интерфейс.',
 'Нельзя полагаться на интерфейсную проверку данных: сервер тоже должен проверять тип и допустимый диапазон. Учебный пример показывает ограничение количества элементов.',
 '''
    def safe_limit(value):
        try:
            n = int(value)
        except (TypeError, ValueError):
            return 10
        return max(1, min(n, 100))

    for x in ("20", "bad", "100000"):
        print(safe_limit(x))
 ''', '20\\n10\\n100',
 'Почему мало проверять ввод только в браузере?',
 ['Его легко обойти прямым запросом к серверу','Потому что Python не понимает строки','Потому что проверка мешает циклам'],0,
 'Любое клиентское ограничение можно обойти. Критичные проверки должны выполняться на доверенной стороне.',
 [('Python: tutorial','https://docs.python.org/3/tutorial/controlflow.html'),('OWASP: Input Validation','https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html')], 'Валидация'),
 topic(5,'Структуры данных: list, dict, set, tuple','Разработка и анализ',
 'Выбор подходящей коллекции ускоряет анализ событий и помогает строить защитные механизмы.',
 'Журналы авторизации','Массовые ошибки входа','Частота по IP-адресам',
 'Счётчик Counter / dict','Сравнить частоты, не только итоговое число',
 ['Выбирать коллекцию под задачу','Подсчитывать частоты по ключу','Объяснять отличие списка от множества'],
 'В журнале десятки тысяч событий: какой IP чаще остальных не может войти? Вручную смотреть все строки бесполезно.',
 'Словарь хранит соответствие «ключ → значение», а Counter сокращает запись частотного подсчёта. Множество удобно для быстрой проверки принадлежности, но не хранит количество повторений.',
 '''
    from collections import Counter
    failed_ips = ["10.0.0.2", "10.0.0.3", "10.0.0.2", "10.0.0.2"]
    counts = Counter(failed_ips)
    print(counts["10.0.0.2"])
    print(sorted(counts.items()))
 ''', "3\\n[('10.0.0.2', 3), ('10.0.0.3', 1)]",
 'Почему set недостаточно, чтобы посчитать число ошибок с каждого IP?',
 ['Множество убирает повторения','Множество всегда сортирует данные','Множество хранит только числа'],0,
 'Для подсчёта частот нужен словарь или Counter. В множестве повторяющиеся элементы сливаются.',
 [('Python: collections','https://docs.python.org/3/library/collections.html'),('Python: структуры данных','https://docs.python.org/3/tutorial/datastructures.html')], 'Анализ логов'),
 topic(6,'Практикум по коллекциям и анализу логов','Разработка и анализ',
 'Сопоставление событий, фильтрация адресов и работа с данными: закрепление структур данных.',
 'Сетевой журнал','Подозрительные адреса','Повторяющиеся записи',
 'Проверка IP и анализ частот','Отделить факт от гипотезы',
 ['Проверять IP через стандартную библиотеку','Группировать результаты по ключу','Не путать подозрительность с доказательством'],
 'В Сигнал поступили строки из журнала входа, часть из них содержит некорректные IP. Прежде чем строить отчёт, данные надо проверить.',
 'Библиотека ipaddress умеет разбирать IPv4 и IPv6. Проверка адреса необходима до группировки, но сам по себе частый IP не доказывает, что это злоумышленник.',
 '''
    from collections import Counter
    import ipaddress
    raw = ["192.0.2.7", "wrong", "192.0.2.7", "2001:db8::1"]
    valid = []
    for item in raw:
        try:
            valid.append(str(ipaddress.ip_address(item)))
        except ValueError:
            pass
    print(sorted(Counter(valid).items()))
 ''', "[('192.0.2.7', 2), ('2001:db8::1', 1)]",
 'Как правильно интерпретировать десять попыток входа с одного адреса?',
 ['Немедленно обвинить владельца IP','Проверить контекст и другие сигналы','Игнорировать события'],1,
 'IP может относиться к общему шлюзу, прокси или NAT; оценка зависит от контекста.',
 [('Python: ipaddress','https://docs.python.org/3/library/ipaddress.html'),('OWASP: Logging','https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html')], 'Расследование'),
 topic(7,'ООП: объекты и инкапсуляция','Объектная модель защиты',
 'Переносим правила безопасности из разрозненных проверок в методы и состояние объектов.',
 'Состояние аккаунта','Изменение состояния напрямую','Недопустимый статус',
 'Методы с проверкой инвариантов','Нельзя получить отрицательное число попыток',
 ['Отличать класс от экземпляра','Понимать self и методы','Сохранять инварианты объекта'],
 'Для каждого аккаунта нужно вести счётчик неудачных входов, но никто не должен изменять его произвольно.',
 'Инкапсуляция — не криптографическая защита, а способ организации логики. В Python один подчёркивающий префикс — соглашение, а двойное подчёркивание даёт name mangling, но не абсолютную секретность.',
 '''
    class LoginState:
        def __init__(self):
            self._failed = 0

        def register_failure(self):
            self._failed += 1

        @property
        def failed(self):
            return self._failed

    state = LoginState()
    state.register_failure()
    print(state.failed)
 ''', '1',
 'Что даёт инкапсуляция в этом примере?',
 ['Гарантирует шифрование поля','Собирает правила изменения состояния в методах','Запрещает любые изменения объекта'],1,
 'Приватность имени в Python не равна механизму разграничения доступа. Правила необходимо проверять на уровне бизнес-логики.',
 [('Python: Classes','https://docs.python.org/3/tutorial/classes.html'),('OWASP: Proactive Controls','https://owasp.org/www-project-proactive-controls/')], 'Инкапсуляция'),
 topic(8,'ООП: свойства и контроль доступа','Объектная модель защиты',
 'Свойства, валидация и защита от Mass Assignment — актуальные модели ошибок доступа.',
 'Атрибуты профиля','Mass Assignment','Изменённое поле role',
 'Белый список полей для изменения','Проверить запрет на изменение роли',
 ['Отличать @property от обычного поля','Понимать Mass Assignment','Реализовывать белый список полей'],
 'При обновлении профиля пользователь передал поле role=admin вместе с именем. Приложение не должно автоматически переносить каждое поле в объект.',
 'Не стоит делать setattr(user, key, value) для всех пришедших от клиента полей. Проверять нужно разрешённые поля, права субъекта и ограничения значений.',
 '''
    profile = {"display_name": "Ира", "role": "student"}
    incoming = {"display_name": "Ирина", "role": "admin"}
    editable = {"display_name"}
    for key in editable & incoming.keys():
        profile[key] = incoming[key]
    print(profile)
 ''', "{'display_name': 'Ирина', 'role': 'student'}",
 'Что предотвратило повышение роли?',
 ['Свойство @property само по себе','Проверка только на клиенте','Явный список разрешённых полей'],2,
 'Белый список определяет, какие поля разрешено изменять через данный интерфейс. Реальные сервисы дополнительно проверяют права.',
 [('OWASP: Mass Assignment','https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'),('Python: property','https://docs.python.org/3/library/functions.html#property')], 'Контроль доступа'),
 topic(9,'ООП: роли и авторизация','Объектная модель защиты',
 'От классов к модели прав: проверяем, кто и какое действие может выполнить.',
 'Права на ресурс','Повышение привилегий','Недопустимое действие',
 'Проверка роли в доверенном коде','Запретить действие при отсутствии права',
 ['Отделять аутентификацию от авторизации','Проверять права на каждый запрос','Применять принцип минимальных привилегий'],
 'Ученик пытается открыть функцию редактирования чужих оценок через прямой запрос, даже если кнопку в интерфейсе ему не показывают.',
 'Скрытая кнопка не защищает серверный метод. Авторизация проверяется там, где выполняется действие, с учётом конкретного пользователя и ресурса.',
 '''
    def can_edit_grades(role):
        return role == "teacher"

    for role in ("student", "teacher"):
        print(role, can_edit_grades(role))
 ''', 'student False\\nteacher True',
 'Где должна выполняться критичная проверка прав?',
 ['Только при отображении кнопок','В доверенной серверной логике при каждом действии','В комментариях к коду'],1,
 'Обход клиентского интерфейса не должен давать дополнительных полномочий.',
 [('OWASP: Authorization','https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'),('OWASP: Access Control','https://owasp.org/Top10/A01_2021-Broken_Access_Control/')], 'Авторизация'),
 topic(10,'ООП: безопасные методы и аудит','Объектная модель защиты',
 'Закрепляем инкапсуляцию на журнале событий, инвариантах и предсказуемых методах.',
 'История операций','Подмена журнала из интерфейса','Неожиданное изменение записи',
 'Ограниченный API и снимок истории','Проверить состояние до и после вызова',
 ['Проектировать методы вместо прямой записи в поле','Возвращать копию изменяемого списка','Не считать защиту на уровне Python абсолютной'],
 'Журнал действий нужен для разбора инцидентов. Объект должен позволять добавлять записи, но не раздавать наружу ссылку на внутренний список.',
 'Возврат копии снижает риск случайной мутации через API. Однако для доказуемого аудита в промышленной системе нужны защищённое хранилище, контроль целостности, права и политика хранения.',
 '''
    class AuditTrail:
        def __init__(self):
            self._events = []

        def add(self, event):
            self._events.append(str(event))

        def snapshot(self):
            return tuple(self._events)

    audit = AuditTrail()
    audit.add("LOGIN_OK")
    print(audit.snapshot())
 ''', "('LOGIN_OK',)",
 'Зачем snapshot() возвращает tuple?',
 ['Чтобы запретить пользователю добавлять события навсегда','Чтобы дать снаружи снимок, не доступ к внутреннему списку','Чтобы зашифровать события'],1,
 'Кортеж — неизменяемая последовательность, но сам по себе он не заменяет защищённый журнал аудита.',
 [('OWASP: Logging','https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'),('Python: classes','https://docs.python.org/3/tutorial/classes.html')], 'Аудит'),
 topic(11,'Стойкая случайность и байтовые данные','Криптографическая защита',
 'PRNG, CSPRNG, secrets, bytes, кодировки и XOR в задачах защиты информации.',
 'Токены восстановления','Предсказуемый токен','Повторение токенов',
 'CSPRNG через secrets','Не использовать random для токенов',
 ['Различать PRNG и CSPRNG','Понимать str и bytes','Объяснять назначение secrets'],
 'Сервис создаёт ссылку восстановления доступа. Если нападающий может угадать токен, чужая учётная запись оказывается под угрозой.',
 'Модуль random полезен для моделирования, но не предназначен для генерации секретов. Для токенов применяется secrets, который опирается на криптографически стойкий источник ОС.',
 '''
    import secrets
    token = secrets.token_urlsafe(24)
    print("Токен создан:", bool(token))
    print("Тип:", type(token).__name__)
 ''', 'Токен создан: True\\nТип: str (сам токен каждый раз новый)',
 'Почему random.random() не годится для токенов доступа?',
 ['Потому что может быть предсказуемым и не предназначен для секретов','Потому что выдаёт только целые числа','Потому что нельзя импортировать модуль'],0,
 'Для секретных токенов используем CSPRNG; диапазон чисел и формат вывода не заменяют свойств генератора.',
 [('Python: secrets','https://docs.python.org/3/library/secrets.html'),('Python: random','https://docs.python.org/3/library/random.html')], 'Криптография'),
 topic(12,'Токены, байты и проверка секретов','Криптографическая защита',
 'Закрепление CSPRNG, безопасного сравнения и представления бинарных данных.',
 'Секреты сессии','Утечка через сравнение по времени','Разное время проверки',
 'hmac.compare_digest и управление сессиями','Проверить без вывода секретных значений',
 ['Понимать сравнение hmac.compare_digest','Понимать назначение кодирования в bytes','Не путать XOR-контрольную сумму с криптохешем'],
 'Проверяем одноразовый код подтверждения: система должна сравнивать его без лишних различий по времени выполнения и не печатать значения в журнал.',
 'compare_digest уменьшает риск некоторых атак по времени при сравнении строк или байтов совместимых типов. Это лишь часть защиты: необходимы ещё сроки действия, ограничение попыток и безопасное хранение.',
 '''
    import hmac
    expected = b"demo-code-123"  # Только учебные данные!
    received = b"demo-code-123"
    ok = hmac.compare_digest(expected, received)
    print("Совпадение:", ok)
 ''', 'Совпадение: True',
 'Что НЕ обеспечивает hmac.compare_digest?',
 ['Сравнение совместимых значений','Полный жизненный цикл и защиту токена','Снижение некоторых рисков по времени сравнения'],1,
 'Безопасное сравнение не заменяет срок действия, ограничение попыток, ротацию и защищённое хранение.',
 [('Python: hmac','https://docs.python.org/3/library/hmac.html'),('OWASP: Session Management','https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'),('NIST SP 800-63B','https://pages.nist.gov/800-63-4/sp800-63b.html')], 'Безопасная проверка'),
]
from module1_extension import extended_topics
LESSONS.extend(extended_topics(topic))
GROUPS=[
 ('I','ФУНДАМЕНТ','Основы защиты','Определяем, какие данные защищать и почему это важно.', 'blue'),
 ('II','ИНСТРУМЕНТЫ','Разработка и анализ','Создаём безопасную среду и разбираем события на Python.','mint'),
 ('III','АРХИТЕКТУРА','Объектная модель защиты','Строим объекты с контролируемым состоянием и правами.','amber'),
 ('IV','КРИПТОГРАФИЯ','Криптографическая защита','Защищаем токены, исследуем генераторы и проводим аудит.','violet'),
 ('V','АТТЕСТАЦИЯ','Аттестация','Завершаем модуль комплексной проверкой знаний и практики.','rose'),
]

THEME = r'''<style id="kd-course-theme">
/* KD design tokens are intentionally scoped: the original lesson CSS/JS is preserved. */
.kd-wrap{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;color:#e8f4f5;line-height:1.48;box-sizing:border-box}
.kd-wrap *{box-sizing:border-box}.kd-wrap a{color:inherit}.kd-top,.kd-foot,.kd-enhance{isolation:isolate;position:relative}
.kd-top{background:#081a27;color:#e9f4f5;border-bottom:2px solid #367e8c;box-shadow:0 9px 32px #091f2822;z-index:150;}
.kd-topin{max-width:1370px;margin:auto;padding:11px 24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.kd-top a{display:inline-flex;align-items:center;gap:7px;text-decoration:none!important;font-size:13px!important;font-weight:650;padding:8px 12px;border-radius:11px;border:1px solid #355365!important;background:#102b3b;color:#e7f5f6!important;line-height:1.25}
.kd-top a:hover{background:#1d4655;color:white!important}.kd-logo{display:inline-flex;align-items:center;gap:8px;font-weight:800;letter-spacing:-.02em;font-size:14px;margin-right:auto;color:#e9f4f5}.kd-logo svg{width:25px;height:25px;fill:none;stroke:#81dacd;stroke-width:1.8}
.kd-counter{color:#a8c5cf;font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin:0 8px}
.kd-top .kd-current{background:#226275;border-color:#3ba5b4;color:#fff!important}
.kd-enhance{max-width:1190px;margin:38px auto 60px;padding:0 24px;color:#e7f2f5;}
.kd-enhance a{color:#9de1db!important}.kd-enhance p{margin:0 0 13px;color:#c6dbe2}.kd-enhance h2,.kd-enhance h3{color:#f2f8fa;line-height:1.2;margin:0 0 15px;letter-spacing:-.03em}.kd-enhance h2{font-size:clamp(23px,3.4vw,36px)}.kd-enhance h3{font-size:19px}
.kd-panel{background:linear-gradient(145deg,#102737,#0b1e2d);border:1px solid #254558;border-radius:23px;overflow:hidden;box-shadow:0 25px 65px #001e2a18}
.kd-panelhead{padding:30px 31px 18px;display:flex;align-items:flex-start;justify-content:space-between;gap:22px;flex-wrap:wrap}
.kd-eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.18em;color:#8fd9d3;font-weight:780;margin-bottom:12px}.kd-lede{font-size:16px;color:#d0e2e7!important;max-width:840px}.kd-status{white-space:nowrap;background:#153e4b;border:1px solid #357e86;color:#abeee4;padding:8px 12px;border-radius:100px;font-size:12px;font-weight:750}
.kd-goals{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px;padding:0 31px 20px}.kd-goal{background:#143141;border:1px solid #284858;padding:13px 14px;border-radius:13px;font-size:13px;color:#d5e9ed}.kd-goal:before{content:"✓";color:#82e0bf;font-weight:900;margin-right:7px}
.kd-map{background:#091a27;padding:20px 26px;border-block:1px solid #294456;overflow-x:auto}.kd-map svg{display:block;width:100%;min-width:680px;height:auto;max-height:230px}.kd-map figcaption{font-size:12px;color:#99bec7;margin-top:8px}
.kd-split{display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:26px 31px}.kd-box{border:1px solid #294758;border-radius:17px;padding:22px;background:#132d3d;min-width:0}.kd-box strong{color:#f7d6a0}.kd-box p,.kd-box li{font-size:14px;line-height:1.7;color:#c9dde3}.kd-box code{color:#b3f0df}
.kd-panel pre{background:#061521;border:1px solid #294554;color:#d5eef1;padding:21px;border-radius:15px;margin:0;white-space:pre;overflow:auto;font-size:13px;line-height:1.65;tab-size:4}.kd-panel pre code{color:inherit!important;font:inherit}
.kd-lab{padding:0 31px 30px}.kd-labbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}.kd-labbar h3{margin:0}.kd-copy{background:#1f6a73!important;color:white!important;border:1px solid #4aa0a9!important;border-radius:9px!important;padding:9px 13px!important;cursor:pointer;font-size:13px;font-weight:700;letter-spacing:0!important}
.kd-copy:hover{background:#25818a!important}.kd-output{padding:11px 16px;background:#102f36;color:#a8ebc8;border:1px solid #2a5a55;border-radius:0 0 13px 13px;font-size:13px;white-space:pre-wrap;word-break:break-word}.kd-output b{color:#d0f5ef}
.kd-quiz{padding:25px 31px 29px;background:#102738;border-top:1px solid #2b4b5e}.kd-options{display:grid;grid-template-columns:1fr;gap:9px;margin:14px 0}.kd-option{display:block;width:100%;text-align:left!important;border:1px solid #315466!important;background:#1a3545!important;color:#e9f4f5!important;border-radius:11px!important;padding:11px 15px!important;font-size:14px!important;line-height:1.6!important;cursor:pointer}.kd-option:hover{border-color:#59abb3!important;background:#204757!important}.kd-option.kd-good{background:#174c42!important;border-color:#65bf94!important}.kd-option.kd-bad{background:#543035!important;border-color:#bc7380!important}.kd-feedback{padding:10px 13px;min-height:36px;font-size:14px;line-height:1.65;color:#cee6e9}
.kd-complete{background:#c6eadf!important;color:#10352f!important;padding:12px 18px!important;font-size:14px!important;font-weight:800;border:0!important;border-radius:12px!important;cursor:pointer}
.kd-complete:hover{background:#e0fff0!important}.kd-complete[aria-pressed="true"]{background:#2a765a!important;color:#e6fffa!important}.kd-resources{display:flex;flex-wrap:wrap;gap:9px;padding:18px 31px 28px;border-top:1px solid #294758}.kd-resources a{font-size:13px!important;border:1px solid #366275;border-radius:9px;padding:9px 12px;text-decoration:none!important;background:#133648}.kd-resources a:hover{background:#245568}
.kd-foot{background:#091b28;color:#effafa;border-top:1px solid #2b5661;padding:25px 24px}.kd-footin{max-width:1170px;margin:auto;display:flex;align-items:center;gap:14px;justify-content:space-between;flex-wrap:wrap}.kd-foot h2{font-size:20px;margin:0 0 5px;color:#effafa}.kd-foot p{font-size:13px;color:#a2bec8;margin:0}.kd-foot a{display:inline-flex;align-items:center;justify-content:center;text-decoration:none!important;padding:11px 16px;border:1px solid #406a75!important;background:#163748;color:#e9f5f5!important;border-radius:11px;font-weight:750;font-size:14px!important}.kd-foot a:hover{background:#216079}.kd-foot a.kd-next{background:#a7ddcb;color:#123c38!important;border-color:#a7ddcb!important}
@media(max-width:800px){.kd-topin{padding:10px 13px}.kd-logo{width:100%}.kd-top a{padding:8px;font-size:12px!important}.kd-enhance{padding:0 13px}.kd-goals{grid-template-columns:1fr;padding:0 18px 18px}.kd-panelhead{padding:23px 19px 15px}.kd-split{grid-template-columns:1fr;padding:18px;gap:12px}.kd-lab{padding:0 18px 20px}.kd-quiz{padding:20px 18px}.kd-resources{padding:18px}.kd-counter{display:none}.kd-map{padding:12px}}
@media(max-width:780px){body:has(#kd-mission[data-kd-lesson="1"]) .grid2,body:has(#kd-mission[data-kd-lesson="1"]) .grid3,body:has(#kd-mission[data-kd-lesson="1"]) .grid4{grid-template-columns:minmax(0,1fr)!important}body:has(#kd-mission[data-kd-lesson="1"]) .surface{min-width:0;max-width:100%}body:has(#kd-mission[data-kd-lesson="1"]) .surface pre{max-width:100%;overflow:auto}}
@media(prefers-reduced-motion:reduce){.kd-wrap *{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
</style>'''

# Unicode-sensitive SVG strings are escaped before interpolation.
def esc(x): return html.escape(str(x), quote=True)

def simple_shield():
 return '<svg viewBox="0 0 28 28" role="img" aria-label="щит"><path d="M14 2 24 6v7c0 7-4 10-10 13C8 23 4 20 4 13V6z"/><path d="m9 14 3.4 3.4L19 10"/></svg>'

def diagram(t):
 fields=[('АКТИВ',t['asset'],'#c3e8ff'),('УГРОЗА',t['threat'],'#f0bd92'),('СИГНАЛ',t['signal'],'#e2d3a1'),('ЗАЩИТА',t['control'],'#9be3d5'),('ПРОВЕРКА',t['verify'],'#ccd3fc')]
 w=202; gap=12; margin=8; out=[]
 out.append('<svg viewBox="0 0 1080 214" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Схема: от актива и угрозы к сигналу, защите и проверке">')
 out.append('<defs><linearGradient id="kdgv" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#15394d"/><stop offset="1" stop-color="#112c3c"/></linearGradient></defs>')
 for idx,(label,val,color) in enumerate(fields):
  x=margin+idx*(w+gap)
  if idx:
   out.append(f'<line x1="{x-gap+2}" y1="95" x2="{x-5}" y2="95" stroke="#6b9eaa" stroke-width="2" stroke-dasharray="3 3"/>')
   out.append(f'<path d="M{x-9} 90 l5 5 -5 5" fill="none" stroke="#6b9eaa" stroke-width="2"/>')
  out.append(f'<rect x="{x}" y="18" rx="14" width="{w}" height="161" fill="url(#kdgv)" stroke="#335d70"/>')
  out.append(f'<rect x="{x+14}" y="34" rx="4" width="5" height="21" fill="{color}"/>')
  out.append(f'<text x="{x+29}" y="49" fill="{color}" font-family="Arial,sans-serif" font-size="13" font-weight="700" letter-spacing="1">{esc(label)}</text>')
  words=val.split(); lines=[]; row=''
  for word in words:
   if len(row+' '+word)>17 and row: lines.append(row);row=word
   else:row=(row+' '+word).strip()
  if row:lines.append(row)
  for j,line in enumerate(lines[:3]):
   out.append(f'<text x="{x+16}" y="{78+j*24}" fill="#e3f3f6" font-family="Arial,sans-serif" font-size="16">{esc(line)}</text>')
  out.append(f'<text x="{x+16}" y="159" fill="#668e9e" font-family="monospace" font-size="12">0{idx+1} / 05</text>')
 out.append('</svg>');return ''.join(out)

def lesson_header(t):
 n=t['n']; prev=f'lesson_{n-1}.html' if n>1 else 'index.html'; nxt=('PA_1.html' if n==14 else (f'lesson_{n+1}.html' if n<14 else 'index.html'))
 return f'''<div class="kd-wrap kd-top" aria-label="Навигация курса Код будущего"><div class="kd-topin">
  <div class="kd-logo">{simple_shield()}<span>КОД БУДУЩЕГО <span style="color:#80b5c4;font-weight:500">/ SECURITY LAB</span></span></div>
  <span class="kd-counter">ЗАНЯТИЕ {n:02d} / 15</span>
  <a href="index.html" aria-label="Оглавление курса">▦ Оглавление</a>
  <a href="{prev}" aria-label="Предыдущее занятие">← Назад</a>
  <a class="kd-current" href="#kd-mission">⊕ Кейс урока</a>
  <a href="{nxt}" aria-label="Следующее занятие">Вперёд →</a>
 </div></div>'''

def extras(t):
 n=t['n']; goals=''.join(f'<div class="kd-goal">{esc(x)}</div>' for x in t['goals'])
 res=''.join(f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(title)} ↗</a>' for title,url in t['references'])
 options=''.join(f'<button class="kd-option" type="button" data-kd-answer="{i}" onclick="kdLessonAnswer{n}(this,{i})">{esc(o)}</button>' for i,o in enumerate(t['options']))
 qdata=json.dumps({'c':t['correct'],'why':t['rationale']},ensure_ascii=False).replace('</','<\\/')
 # Avoid interpolating code as executable script; code lives in escaped text node.
 code=html.escape(t['code'])
 return f'''<div class="kd-wrap kd-enhance" id="kd-mission" data-kd-lesson="{n}">
 <div class="kd-panel">
  <div class="kd-panelhead">
   <div><div class="kd-eyebrow">Единый сквозной кейс / Портал «Сигнал» · миссия {n:02d}</div>
   <h2>Безопасность на практике: {esc(t['tag'])}</h2>
   <p class="kd-lede">{esc(t['summary'])}</p></div>
   <span class="kd-status">● Разбор → код → проверка</span>
  </div>
  <div class="kd-goals">{goals}</div>
  <figure class="kd-map" style="margin:0">{diagram(t)}<figcaption>Универсальная логика курса: защищаемый актив → потенциальная угроза → наблюдаемый сигнал → контроль → способ проверки. Сигнал сам по себе не доказывает атаку.</figcaption></figure>
  <div class="kd-split">
   <div class="kd-box"><h3>▣ Ситуация из практики</h3><p>{esc(t['story'])}</p><p><strong>Актив:</strong> {esc(t['asset'])}. <strong>Угроза:</strong> {esc(t['threat'])}.</p></div>
   <div class="kd-box"><h3>◉ Разбираем причинно-следственную связь</h3><p>{esc(t['explanation'])}</p><p><strong>Что проверяем:</strong> {esc(t['verify'])}.</p></div>
  </div>
  <div class="kd-lab"><div class="kd-labbar"><h3>⌘ Python · фрагмент для самостоятельной проверки</h3><button class="kd-copy" type="button" id="kd-copy-{n}">⧉ Скопировать код</button></div>
  <pre><code id="kd-code-{n}">{code}</code></pre><div class="kd-output"><b>Ожидаемый результат:</b>\n{esc(t['expected'].replace('\\n',chr(10)))}</div>
  <p style="font-size:12px;margin:12px 0 0;color:#a9c7d0">Код запускается в Python 3 и использует только стандартную библиотеку. Эксперименты выполняйте на учебных данных и в разрешённом окружении.</p></div>
  <div class="kd-quiz"><div class="kd-eyebrow">Проверь понимание / Задание без оценки</div><h3>{esc(t['quiz'])}</h3>
   <div class="kd-options" id="kd-answers-{n}">{options}</div>
   <div class="kd-feedback" id="kd-feedback-{n}" aria-live="polite">Выберите вариант, чтобы увидеть пояснение.</div>
   <button type="button" class="kd-complete" id="kd-complete-{n}" aria-pressed="false">✓ Отметить урок пройденным</button>
  </div>
  <div class="kd-resources"><span style="flex-basis:100%;font-size:11px;text-transform:uppercase;letter-spacing:.16em;color:#9fc6d0;font-weight:700">Достоверные источники и дальнейшее чтение</span>{res}</div>
 </div>
</div>
<script id="kd-script-{n}">
(function(){{
 'use strict';
 var n={n}, key='kod_bud_v3_done_'+n;
 var q={qdata};
 var answered=false;
 var btn=document.getElementById('kd-complete-'+n);
 function updateState(){{
  var done=false; try{{done=localStorage.getItem(key)==='1'}}catch(e){{}}
  btn.setAttribute('aria-pressed',String(done));
  btn.textContent=done?'✓ Урок отмечен пройденным':'✓ Отметить урок пройденным';
 }}
 window['kdLessonAnswer'+n]=function(node,index){{
  var all=document.querySelectorAll('#kd-answers-'+n+' .kd-option');
  all.forEach(function(x){{x.classList.remove('kd-good','kd-bad')}});
  node.classList.add(index===q.c?'kd-good':'kd-bad');
  all[q.c].classList.add('kd-good');
  document.getElementById('kd-feedback-'+n).textContent=(index===q.c?'Верно. ':'Верный ответ выделен. ')+q.why;
 }};
 btn.addEventListener('click',function(){{
  try{{localStorage.setItem(key,btn.getAttribute('aria-pressed')==='true'?'0':'1')}}catch(e){{}}
  updateState();
 }});
 document.getElementById('kd-copy-'+n).addEventListener('click',function(e){{
  var b=e.currentTarget;var code=document.getElementById('kd-code-'+n).textContent;
  function success(){{b.textContent='✓ Скопировано';setTimeout(function(){{b.textContent='⧉ Скопировать код'}},2100)}}
  if(navigator.clipboard && window.isSecureContext){{navigator.clipboard.writeText(code).then(success).catch(fallback)}}
  else fallback();
  function fallback(){{var ta=document.createElement('textarea');ta.value=code;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();try{{document.execCommand('copy');success()}}finally{{ta.remove()}}}}
 }});
 updateState();
}})();
</script>'''

def lesson_footer(t):
 n=t['n']; pr=f'lesson_{n-1}.html' if n>1 else 'index.html';nx=('PA_1.html' if n==14 else (f'lesson_{n+1}.html' if n<14 else 'index.html'))
 ptext=f'← Урок {n-1}' if n>1 else '← К оглавлению';ntext=('Аттестация →' if n==14 else f'Урок {n+1} →') if n<15 else 'К оглавлению →'
 return f'''<footer class="kd-wrap kd-foot" aria-label="Навигация между уроками"><div class="kd-footin"><div><div class="kd-eyebrow">КОД БУДУЩЕГО / ЗАНЯТИЕ {n:02d} ИЗ 15</div><h2>{'Модуль 1 завершён' if n==15 else 'Путь защитника продолжается'}</h2><p>Принцип каждого урока: понять угрозу · написать безопасный код · проверить результат</p></div><div style="display:flex;gap:10px;flex-wrap:wrap"><a href="{pr}">{ptext}</a><a href="index.html">Все 15 занятий</a><a class="kd-next" href="{nx}">{ntext}</a></div></div></footer>'''

START='<!-- KD_COURSE_' ; END='<!-- /KD_COURSE_' 

def strip_block(s, name):
 # Only marked text is removed: surrounding original bytes, including newlines,
 # remain untouched. This works for minified and prettified HTML alike.
 return re.sub(r'<!-- KD_COURSE_'+name+r' -->(.*?)<!-- /KD_COURSE_'+name+r' -->','',s,flags=re.S)

def wrap_part(name,content):
 return f'<!-- KD_COURSE_{name} -->\n{content}\n<!-- /KD_COURSE_{name} -->'

def inject_lesson(src,t):
 s=src
 for k in ('HEAD','TOP','EXTRA','FOOT'):
  s=strip_block(s,k)
 if not re.search(r'</head\s*>',s,re.I) or not re.search(r'<body\b[^>]*>',s,re.I) or not re.search(r'</body\s*>',s,re.I):
  raise ValueError(f"bad HTML document {t['path']}")
 s=re.sub(r'</head\s*>',wrap_part('HEAD',THEME)+'</head>',s,count=1,flags=re.I)
 s=re.sub(r'<body\b[^>]*>',lambda m:m.group(0)+wrap_part('TOP',lesson_header(t)),s,count=1,flags=re.I)
 i=list(re.finditer(r'</body\s*>',s,re.I))[-1].start()
 s=s[:i]+wrap_part('EXTRA',extras(t))+wrap_part('FOOT',lesson_footer(t))+s[i:]
 return s

INDEX_CSS=r'''
:root{--bg:#071621;--surface:#102634;--panel:#0c202d;--line:#23475a;--ink:#eaf5f5;--soft:#abc9d2;--mint:#8addcb;--amber:#f4c484;--blue:#96cce8;--violet:#c3b4f0;--radius:20px}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Arial,sans-serif}button,input{font:inherit}button{cursor:pointer}a{color:inherit}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #86ddd3;outline-offset:4px}::selection{color:#002c32;background:#9be3d1}
.container{width:min(1230px,calc(100% - 40px));margin:auto}.stripe{height:3px;background:linear-gradient(90deg,#2c8fa5,#9de0c8 54%,#e2b77c)}
.top{position:sticky;top:0;z-index:30;background:#081923ed;border-bottom:1px solid #31515f;backdrop-filter:blur(20px)}.topin{display:flex;gap:20px;justify-content:space-between;align-items:center;padding:13px 0}.brand{display:flex;gap:10px;align-items:center;text-decoration:none;font-weight:830;letter-spacing:-.02em;font-size:16px}.brand svg{width:29px;stroke:#9bdfc7;fill:none;stroke-width:1.7}.topnav{display:flex;gap:12px;align-items:center}.topnav a{font-size:13px;text-decoration:none;color:#b0ccd3;padding:8px 13px;border-radius:9px}.topnav a:hover{color:#fff;background:#193f4b}.status-chip{font-size:11px;letter-spacing:.08em;color:#9dddca;border:1px solid #286350;border-radius:100px;padding:7px 10px;text-transform:uppercase}
.hero{position:relative;overflow:hidden;padding:80px 0 72px;background:radial-gradient(ellipse at 79% 15%,#184e595a,transparent 49%),linear-gradient(165deg,#0e2837 0%,#091c2a 58%,#071621)}.hero:before{content:"";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(#83d0d00c 1px,transparent 1px),linear-gradient(90deg,#83d0d00c 1px,transparent 1px);background-size:36px 36px;mask-image:linear-gradient(90deg,transparent,#000)}
.herogrid{display:grid;grid-template-columns:1.12fr .88fr;align-items:center;gap:35px;position:relative}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.19em;color:#8edcce;font-weight:780}.hero h1{font-size:clamp(40px,5vw,78px);font-weight:760;line-height:1.06;letter-spacing:-.055em;margin:15px 0 21px}.hero h1 em{font-style:normal;color:#9edecb}.hero p{max-width:650px;font-size:clamp(17px,1.8vw,20px);color:#b6d4da;line-height:1.72;margin:0 0 26px}.actions{display:flex;gap:11px;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;gap:10px;text-decoration:none;border-radius:11px;padding:12px 20px;font-size:14px;font-weight:750;border:1px solid #416b76;background:#1c4753;color:#e4f7f5}.btn.primary{background:#abdcca;color:#083229;border-color:#abdcca}.btn:hover{transform:translateY(-1px);filter:brightness(1.08)}.btn.ghost{background:#123040}.hero-illustration{position:relative;min-height:330px;border-radius:25px;border:1px solid #326071;background:#091e2d;overflow:hidden;box-shadow:0 24px 65px #00101d70}.hero-illustration svg{width:100%;height:100%;min-height:330px;display:block}.scanner{animation:scan 5s ease-in-out infinite}@keyframes scan{0%,100%{transform:translateY(-50px)}50%{transform:translateY(110px)}}.flow-dot{animation:dash 5s linear infinite}@keyframes dash{from{stroke-dashoffset:110}to{stroke-dashoffset:0}}
.statbar{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #315768;border-radius:17px;background:#0e2936;margin-top:38px;overflow:hidden}.stat{padding:18px 20px;border-right:1px solid #294b5e}.stat:last-child{border-right:none}.stat b{display:block;font-size:25px;font-weight:780;color:#eef9f9;line-height:1.12}.stat span{display:block;color:#9abac7;font-size:12px;margin-top:7px}
main{padding:52px 0 90px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:22px}.section-head h2{font-size:clamp(28px,3vw,42px);line-height:1.15;letter-spacing:-.036em;margin:8px 0}.section-head p{margin:0;color:#9bbac6;max-width:670px;font-size:15px}
.roadmap{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin:21px 0 61px}.road{border:1px solid #315466;background:#112a39;border-radius:17px;padding:20px;min-height:190px;position:relative;overflow:hidden}.road:before{content:"";width:46px;height:4px;position:absolute;top:0;left:20px;background:var(--tone)}.road .num{color:var(--tone);font-size:13px;font-weight:780}.road h3{font-size:19px;line-height:1.2;margin:15px 0 10px;font-weight:730}.road p{color:#a8c5cd;font-size:13px;margin:0}.road .count{margin-top:15px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#b7dae0}
.toolbar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:15px;background:#0e2634;border:1px solid #2d4e60;border-radius:16px;padding:15px;margin-bottom:25px}.search{display:flex;gap:10px;align-items:center;background:#081c29;border:1px solid #355866;color:#a8c9d3;border-radius:12px;padding:10px 14px;min-width:min(440px,100%);flex:1}.search input{width:100%;background:transparent;border:0;color:#edf8f8;outline:none;font-size:14px}.search input::placeholder{color:#89a7b1}.toggles{display:flex;gap:8px;flex-wrap:wrap}.filter{padding:8px 11px;border:1px solid #3b5c6c;border-radius:9px;background:transparent;color:#b4cdd4;font-size:12px}.filter.active{background:#b6ded3;color:#092e2d;border-color:#b6ded3}.check-wrap{display:flex;align-items:center;gap:7px;color:#a8c5cc;font-size:12px;cursor:pointer}.check-wrap input{accent-color:#a8e2ca}
.lesson-group{margin:32px 0 45px}.group-head{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap;border-bottom:1px solid #294b59;padding:0 0 17px;margin-bottom:17px}.group-head .roman{font-size:15px;font-weight:850;color:#b4dacd}.group-head h3{font-size:24px;letter-spacing:-.025em;margin:0}.group-head .description{color:#8fb2be;font-size:13px;margin-left:auto}
.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:15px}.card{display:flex;min-height:205px;flex-direction:column;background:linear-gradient(138deg,#102b39,#0d2230);border:1px solid #294b5d;border-radius:17px;padding:24px;text-decoration:none;position:relative;transition:transform .18s,border-color .18s,background .18s;overflow:hidden}.card:hover{transform:translateY(-3px);border-color:#68b0ab;background:linear-gradient(135deg,#163949,#0d2937)}.card:focus-visible{outline:3px solid #81d3ca;outline-offset:2px}.card .line1{display:flex;align-items:center;justify-content:space-between;gap:10px}.card .id{font:750 12px/1 monospace;color:#9fded1;letter-spacing:.12em}.card .done-pill{border-radius:100px;background:#183b48;color:#8caab7;padding:5px 8px;font-size:11px;white-space:nowrap}.card.completed .done-pill{background:#1c523f;color:#b6ead5}.card h4{font-size:20px;font-weight:760;line-height:1.28;margin:17px 0 10px;letter-spacing:-.025em}.card p{font-size:14px;line-height:1.65;color:#a8c2cd;margin:0 0 23px}.card .bottom{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-top:auto}.tag{font-size:12px;color:#a2cbc5;background:#133746;border:1px solid #315a67;border-radius:7px;padding:5px 9px}.arrow{color:#aee2c9;font-size:21px}
.none{display:none;text-align:center;color:#a9cbd2;padding:38px}.progress-panel{display:flex;gap:30px;align-items:center;flex-wrap:wrap;background:linear-gradient(112deg,#133b43,#102a38);border:1px solid #37636d;border-radius:21px;padding:25px 30px;margin:0 0 65px}.progress-ring{width:99px;height:99px;flex-shrink:0;border-radius:50%;background:conic-gradient(#a7ddc9 var(--pct),#294d5b 0);display:grid;place-items:center}.progress-ring:after{content:"";width:75px;height:75px;border-radius:50%;background:#11313c;grid-area:1/1}.progress-ring b{grid-area:1/1;z-index:1;font-size:24px}.progress-panel h3{font-size:22px;margin:0 0 7px}.progress-panel p{font-size:14px;color:#b2ccd3;margin:0}.progress-panel .btn{margin-left:auto}
.extras{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}.extra{border:1px solid #355666;border-radius:19px;background:#102d3c;padding:27px}.extra .small{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#e8bf85;font-weight:750}.extra h3{font-size:23px;margin:15px 0 8px;line-height:1.2}.extra p{font-size:14px;color:#abc7d0;margin:0 0 19px;line-height:1.65}.extra a{display:inline-flex;align-items:center;gap:10px;font-size:14px;text-decoration:none;font-weight:760;color:#bfe6d5}.extra a:hover{text-decoration:underline}.extra.meta{background:#0e2331}
.footer{border-top:1px solid #2c4a59;padding:24px 0 40px;background:#081923}.footer .inner{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}.footer p{font-size:13px;color:#9bb8c3;margin:0}.footer a{font-size:13px;color:#9bcfc8;text-decoration:none}
@media(max-width:1000px){.herogrid{grid-template-columns:1fr 1fr}.roadmap{grid-template-columns:repeat(2,1fr)}}@media(max-width:760px){.container{width:min(100% - 24px,1230px)}.topnav{gap:4px}.topnav a{padding:5px;font-size:12px}.status-chip{display:none}.hero{padding:46px 0}.herogrid{grid-template-columns:1fr}.hero-illustration{min-height:210px}.hero-illustration svg{min-height:220px}.statbar{grid-template-columns:repeat(2,1fr)}.stat:nth-child(2){border-right:0}.stat:nth-child(-n+2){border-bottom:1px solid #294b5e}.cards,.extras{grid-template-columns:1fr}.toolbar{padding:12px}.group-head .description{margin-left:0}.progress-panel{padding:20px}.progress-panel .btn{margin-left:0}.roadmap{gap:10px}.road{padding:16px;min-height:210px}}
@media(max-width:760px){.topin{flex-wrap:wrap;gap:5px}.brand{width:100%;justify-content:center}.topnav{width:100%;justify-content:space-around}.topnav a{padding:7px 9px;font-size:13px}}
@media(max-width:480px){.roadmap{grid-template-columns:1fr}.road{min-height:0}.stat{padding:13px}.section-head h2{font-size:29px}.card{padding:19px;min-height:195px}.hero h1{font-size:42px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
'''

def hero_illustration():
 return '''<div class="hero-illustration" aria-hidden="true"><svg viewBox="0 0 530 380" xmlns="http://www.w3.org/2000/svg">
 <defs><pattern id="grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M28 0H0V28" fill="none" stroke="#2b5261" stroke-width=".7"/></pattern><linearGradient id="g" x1="0" x2="1"><stop stop-color="#163b48"/><stop offset="1" stop-color="#112d3a"/></linearGradient></defs>
 <rect width="530" height="380" fill="#081d2a"/><rect width="530" height="380" fill="url(#grid)" opacity=".55"/>
 <rect x="28" y="24" width="474" height="330" rx="18" fill="#0b2331" stroke="#346071"/><circle cx="53" cy="47" r="5" fill="#79c5b7"/><circle cx="71" cy="47" r="5" fill="#ccaa75"/><circle cx="89" cy="47" r="5" fill="#51768b"/>
 <text x="108" y="51" font-family="monospace" fill="#95bfcb" font-size="12">signal.security / telemetry</text><path d="M28 70H502" stroke="#285061"/>
 <rect x="48" y="91" width="275" height="191" rx="12" fill="url(#g)" stroke="#356272"/><text x="63" y="113" fill="#91b7c4" font-family="monospace" font-size="10">EVENT STREAM — LOCAL</text>
 <text x="63" y="148" fill="#97decd" font-family="monospace" font-size="13">✓ AUTH OK</text><text x="63" y="174" fill="#e6ba84" font-family="monospace" font-size="13">! LOGIN FAIL</text><text x="63" y="200" fill="#97decd" font-family="monospace" font-size="13">✓ INPUT VALID</text><text x="63" y="226" fill="#e6ba84" font-family="monospace" font-size="13">! TOKEN EXPIRED</text><text x="63" y="253" fill="#97decd" font-family="monospace" font-size="13">✓ ACCESS DENIED</text>
 <g class="scanner"><rect x="56" y="144" width="256" height="4" rx="2" fill="#75e4ce" opacity=".63"/></g>
 <rect x="345" y="91" width="135" height="190" rx="13" fill="#112f3e" stroke="#326273"/>
 <path d="M413 117 457 132v46c0 33-22 46-44 58-22-12-44-25-44-58v-46z" fill="#1a4c55" stroke="#77cdbb" stroke-width="3"/><path d="m391 178 15 15 27-32" fill="none" stroke="#b5f2d6" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
 <text x="369" y="263" fill="#9edfc9" font-size="12" font-family="monospace">PROTECTED</text>
 <path d="M51 313H477" stroke="#234e5c"/><text x="53" y="335" fill="#92adba" font-family="monospace" font-size="12">ASSET</text><text x="169" y="335" fill="#92adba" font-family="monospace" font-size="12">THREAT</text><text x="295" y="335" fill="#92adba" font-family="monospace" font-size="12">CONTROL</text><text x="419" y="335" fill="#a2e3ca" font-family="monospace" font-size="12">CHECK ✓</text>
 <path class="flow-dot" d="M90 319H466" fill="none" stroke="#9adecb" stroke-width="2" stroke-dasharray="4 26" opacity=".7"/>
 </svg></div>'''

def make_index(available):
 bygroup={g[2]:[t for t in LESSONS if t['module']==g[2]] for g in GROUPS}
 roads=''.join(f'<article class="road" style="--tone:{tone}"><span class="num">ЭТАП {roman}</span><h3>{esc(label)}</h3><p>{esc(desc)}</p><div class="count">{len(bygroup[name])} занятия</div></article>' for roman,label,name,desc,c in GROUPS for tone in [{'blue':'#9ccce5','mint':'#92d8ca','amber':'#eec28c','violet':'#c7b6f0','rose':'#efa8b4'}[c]])
 groups=[]
 for roman,label,name,desc,c in GROUPS:
  cards=[]
  for t in bygroup[name]:
   data=' '.join([t['title'],t['summary'],t['tag'],name]).lower()
   cards.append(f'<a class="card" href="{t["path"]}" data-number="{t["n"]}" data-module="{c}" data-search="{esc(data)}"><div class="line1"><span class="id">ЗАНЯТИЕ {t["n"]:02d} / 15</span><span class="done-pill">○ Не пройден</span></div><h4>{esc(t["title"])}</h4><p>{esc(t["summary"])}</p><div class="bottom"><span class="tag">{esc(t["tag"])}</span><span class="arrow" aria-hidden="true">↗</span></div></a>')
  groups.append(f'<section class="lesson-group" id="group-{c}" data-group="{c}"><div class="group-head"><span class="roman">{roman} / {esc(label)}</span><h3>{esc(name)}</h3><span class="description">{esc(desc)}</span></div><div class="cards">{"".join(cards)}</div></section>')
 index = f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#071621"><meta name="description" content="Код будущего — 14 уроков и промежуточная аттестация Python и информационной безопасности: теория, задачи, тренажёры, решения и визуальные схемы."><title>Код будущего · Модуль 1 | 14 уроков + аттестация</title>
<style>{INDEX_CSS}</style></head>
<body data-kd-catalog="1"><div class="stripe"></div><header class="top"><div class="container topin"><a href="index.html" class="brand">{simple_shield()} КОД БУДУЩЕГО <span style="color:#72bcae;font-size:12px;font-weight:600">/ CYBER LAB</span></a><nav class="topnav" aria-label="Навигация"><a href="#roadmap">Маршрут</a><a href="#lessons">14 уроков</a><a href="#group-rose">Аттестация</a><a href="#extras">Дополнительно</a></nav><div class="status-chip">● PYTHON × SECURITY</div></div></header>
<section class="hero"><div class="container"><div class="herogrid"><div><div class="eyebrow">МОДУЛЬ 1 / PYTHON × CYBERSECURITY · 10–11 классы</div><h1>Изучаем Python.<br><em>Учимся защищать.</em></h1><p>14 взаимосвязанных уроков и промежуточная аттестация по программированию и информационной безопасности. От понимания угроз и законов — до анализа логов, контроля доступа и криптографически стойких токенов.</p><div class="actions"><a class="btn primary" href="lesson_1.html">Начать с урока 01 <span aria-hidden="true">↗</span></a><a class="btn ghost" href="#lessons">Открыть оглавление ↓</a></div></div>{hero_illustration()}</div>
<div class="statbar"><div class="stat"><b>14 + 1</b><span>уроки и аттестация</span></div><div class="stat"><b>5</b><span>последовательных этапов</span></div><div class="stat"><b>Python 3</b><span>примеры с разбором</span></div><div class="stat"><b>Security</b><span>сквозной инженерный кейс</span></div></div></div></section>
<main class="container"><section id="roadmap"><div class="section-head"><div><div class="eyebrow">ЛОГИКА КУРСА</div><h2>Маршрут защитника</h2><p>Не отдельные темы, а единая последовательность: <strong style="color:#bbdfd5">актив → угроза → сигнал → контроль → проверка</strong>. На каждом этапе строим часть защиты учебной платформы «Сигнал».</p></div></div><div class="roadmap">{roads}</div></section>
<section class="progress-panel" aria-label="Прогресс обучения"><div class="progress-ring" id="progressRing" style="--pct:0%"><b id="progressPercent">0%</b></div><div><div class="eyebrow">ЛИЧНЫЙ МАРШРУТ</div><h3 id="progressTitle">Всё готово к старту</h3><p id="progressText">0 из 15 занятий отмечено пройденными. Прогресс сохраняется только в этом браузере.</p></div><a class="btn primary" id="resumeLink" href="lesson_1.html">Продолжить обучение →</a></section>
<section id="lessons"><div class="section-head"><div><div class="eyebrow">СОДЕРЖАНИЕ</div><h2>Модуль 1 · все занятия</h2><p>Поиск по теме, фильтр по разделам и отметки пройденных уроков. Каждый урок открывается отдельной HTML-страницей.</p></div></div><div class="toolbar"><label class="search">⌕ <input id="search" type="search" placeholder="Найти тему, термин или занятие..." autocomplete="off" aria-label="Поиск по урокам"></label><div class="toggles" role="group" aria-label="Фильтры"><button class="filter active" type="button" data-filter="all">Все</button><button class="filter" type="button" data-filter="blue">Основы</button><button class="filter" type="button" data-filter="mint">Python</button><button class="filter" type="button" data-filter="amber">ООП</button><button class="filter" type="button" data-filter="violet">Криптография</button><button class="filter" type="button" data-filter="rose">Аттестация</button></div><label class="check-wrap"><input id="unfinished" type="checkbox"> Только непройденные</label></div>{''.join(groups)}<p id="noResults" class="none">Ничего не найдено. Попробуйте изменить запрос или сбросить фильтры.</p></section>
<section id="extras" style="padding-top:40px"><div class="section-head"><div><div class="eyebrow">БИБЛИОТЕКА ИНСТРУМЕНТОВ</div><h2>Дополнительные материалы</h2><p>Самостоятельные интерактивные страницы: могут использоваться и вне этого курса. Их исходные файлы и прямые ссылки не изменяются.</p></div></div><div class="extras"><article class="extra"><div class="small">Доп. материал 01 / Генеративный ИИ</div><h3>Как нейросеть создаёт изображение</h3><p>Модели генерации, диффузия, GAN, визуальные лаборатории и практика составления промптов.</p><a href="AI_img.html">Открыть AI_img.html →</a></article><article class="extra"><div class="small">Доп. материал 02 / Управление проектами</div><h3>Канбан, устав и бэклог</h3><p>Интерактивный проектный урок, визуализация потока задач и тренажёры принятия решений.</p><a href="AI_kanban.html">Открыть AI_kanban.html →</a></article><article class="extra meta"><div class="small">Документация / Официальный источник</div><h3>Python и безопасная разработка</h3><p>Справочная документация по синтаксису Python, стандартной библиотеке и рекомендациям OWASP.</p><a href="https://docs.python.org/3/" target="_blank" rel="noopener noreferrer">Документация Python ↗</a><br><a href="https://cheatsheetseries.owasp.org/" target="_blank" rel="noopener noreferrer" style="margin-top:10px">OWASP Cheat Sheet Series ↗</a></article></div></section></main>
<footer class="footer"><div class="container inner"><p>© Код будущего · Python и кибербезопасность · 14 уроков + аттестация</p><a href="https://github.com/Altersam/kod_bud" target="_blank" rel="noopener noreferrer">Исходный код на GitHub ↗</a></div></footer>
<script>
(()=>{{'use strict';
const cards=[...document.querySelectorAll('.card')];const groups=[...document.querySelectorAll('.lesson-group')];
const search=document.getElementById('search');const unfinished=document.getElementById('unfinished');const buttons=[...document.querySelectorAll('.filter')];
let active='all';const done=(n)=>{{try{{return localStorage.getItem('kod_bud_v3_done_'+n)==='1'}}catch(e){{return false}}}};
function refresh(){{let count=0;for(const card of cards){{let n=+card.dataset.number;let yes=done(n);if(yes)count++;card.classList.toggle('completed',yes);card.querySelector('.done-pill').textContent=yes?'✓ Пройден':'○ Не пройден'}};
 const pct=Math.round(count/15*100);document.getElementById('progressPercent').textContent=pct+'%';document.getElementById('progressRing').style.setProperty('--pct',pct+'%');
 document.getElementById('progressText').textContent=count+' из 15 занятий отмечено пройденными. Прогресс сохраняется только в этом браузере.';
 document.getElementById('progressTitle').textContent=count===15?'Маршрут пройден!':count===0?'Всё готово к старту':'Хороший темп — продолжайте';
 const next=cards.find(card=>!done(+card.dataset.number));const resume=document.getElementById('resumeLink');resume.href=next?next.getAttribute('href'):'PA_1.html';resume.textContent=next?'Продолжить: урок '+next.dataset.number+' →':'Повторить аттестацию →';filter();}}
function filter(){{let found=0;const q=search.value.trim().toLocaleLowerCase('ru');for(const card of cards){{let ok=(active==='all'||card.dataset.module===active)&&(!q||card.dataset.search.includes(q))&&(!unfinished.checked||!done(+card.dataset.number));card.hidden=!ok;card.style.display=ok?'':'none';if(ok)found++}}for(const g of groups){{const visible=[...g.querySelectorAll('.card')].some(c=>!c.hidden);g.style.display=visible?'':'none'}}document.getElementById('noResults').style.display=found?'none':'block';}}
buttons.forEach(b=>b.addEventListener('click',()=>{{buttons.forEach(x=>x.classList.remove('active'));b.classList.add('active');active=b.dataset.filter;filter()}}));
search.addEventListener('input',filter);unfinished.addEventListener('change',filter);window.addEventListener('storage',refresh);window.addEventListener('pageshow',refresh);refresh();
}})();
</script></body></html>'''
 return index

def verify_docs(root):
 result={}; all_names={p.name for p in root.glob('*.html')}
 for page in sorted([*root.glob('lesson_*.html'), *( [root/'PA_1.html'] if (root/'PA_1.html').exists() else [])]):
  s=page.read_text('utf-8-sig');
  matches=list(re.finditer(r'<(?:a|link|script|img)[^>]+(?:href|src)\s*=\s*(["\'])(.*?)\1',s,re.I|re.S))
  broken=[]
  for m in matches:
   href=html.unescape(m.group(2)).split('#')[0].split('?')[0]
   if re.fullmatch(r'(?:\./)?[\w-]+\.html',href) and Path(href).name not in all_names:
    broken.append(href)
  result[page.name]={'bytes':page.stat().st_size,'courseTop':s.count('KD_COURSE_TOP'),'mission':s.count('KD_COURSE_EXTRA'),'footer':s.count('KD_COURSE_FOOT'),'broken_local_links':sorted(set(broken))}
 return result

def build(root,strict=False):
 root.mkdir(parents=True,exist_ok=True)
 ready=[t for t in LESSONS if (root/t['path']).exists()]
 absent=[t['path'] for t in LESSONS if not (root/t['path']).exists()]
 if strict and absent:
  raise FileNotFoundError('Missing original lessons in root: '+', '.join(absent))
 for t in LESSONS:
  # A syntactically valid example is the minimum QA gate for added Python snippets.
  ast.parse(t['code'],filename=f'new_example_{t["n"]}.py')
 indexfile=root/'index.html'; legacy=root/'extra_structures_legacy.html'
 if indexfile.exists() and not legacy.exists() and 'data-kd-catalog="1"' not in indexfile.read_text('utf-8-sig'):
  shutil.copy2(indexfile,legacy)
 for t in ready:
  file=root/t['path']; src=file.read_text('utf-8-sig'); updated=inject_lesson(src,t)
  if updated!=src:
   file.write_text(updated,encoding='utf-8')
 (root/'index.html').write_text(make_index(ready),encoding='utf-8')
 report={'lessons_available':len(ready),'lessons_missing':absent,'additional_files_untouched':['AI_img.html','AI_kanban.html'],'legacy_original_saved':legacy.exists(),'qa':verify_docs(root)}
 (root/'QA_REPORT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
 return report

if __name__=='__main__':
 parser=argparse.ArgumentParser(description='Build root-level security course without modifying AI HTML files')
 parser.add_argument('--root',default='.',help='Folder containing index.html and lesson_1.html–lesson_14.html and PA_1.html')
 parser.add_argument('--strict',action='store_true',help='Require all 14 lessons and final assessment')
 args=parser.parse_args()
 report=build(Path(args.root),args.strict)
 print('Enhanced lessons:',report['lessons_available'])
 print('Missing originals:',', '.join(report['lessons_missing']) or 'none')
 print('Archived old index:',report['legacy_original_saved'])
 for k,v in report['qa'].items():
  print(k,v['bytes'],'bytes, broken local links:',','.join(v['broken_local_links']) or 'none')
