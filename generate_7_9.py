from pathlib import Path
from html import escape
import json
ROOT=Path(__file__).parent

DATA={
7:{'name':'Объектно-ориентированное программирование: классы и инкапсуляция', 'kicker':'От переменных к объектам с правилами доступа','lead':'Как классы, методы и свойства помогают объединять данные и правила их изменения в понятные безопасные компоненты.',
'intro':('Представьте, что система хранит счётчик неудачных входов в разных частях программы. Если любой модуль может произвольно записать в него −100, данные аудита становятся недостоверными. ООП позволяет определить объект состояния и разрешённые операции с ним.','Инкапсуляция не обеспечивает шифрование: это архитектурный принцип. В Python приватность атрибутов существует в основном на уровне соглашений; даже двойное подчёркивание не создаёт непробиваемого контроля доступа.'),
'concepts': [('Класс и экземпляр','Класс определяет структуру и поведение, экземпляр хранит собственное состояние. `self` — ссылка на текущий экземпляр, а не специальное ключевое слово.'),('Методы и состояние','Метод описывает допустимое действие над состоянием. Проверка должна выполняться в методе, а не полагаться на кнопку интерфейса.'),('Инкапсуляция','Пользователь объекта работает через публичный API. Атрибут `_failed` показывает намерение не изменять поле напрямую, но технически доступен.'),('Наследование и полиморфизм','Наследование переиспользует поведение, полиморфизм позволяет обращаться к разным реализациям через одинаковый интерфейс. Не наследуйте класс лишь ради нескольких строк кода.'),('Декоратор','Декоратор оборачивает функцию дополнительной логикой, например проверкой полномочий, протоколированием или кешированием.'),('Хэш и секреты','Пароли нельзя хранить или сравнивать как обычные строки в учебной модели сервера. Для реального хранения нужны медленные алгоритмы хэширования паролей с солью и параметры, соответствующие рекомендациям OWASP.')],
'cases':[('Класс LoginMonitor: защита инварианта', '''class LoginMonitor:
    def __init__(self, limit=3):
        if limit < 1:
            raise ValueError('limit must be positive')
        self._limit = limit
        self._failed = 0

    def fail(self):
        self._failed += 1
        return self._failed >= self._limit

    def reset_after_success(self):
        self._failed = 0

    @property
    def attempts(self):
        return self._failed

monitor = LoginMonitor(3)
for _ in range(3):
    print(monitor.fail(), monitor.attempts)''', 'False 1\nFalse 2\nTrue 3','Счётчик меняется только через предусмотренные методы. Порог срабатывания имеет смысл только вместе с политикой блокировки, логированием и защитой от массовых запросов.'),
('Полиморфизм: единый контракт для разных факторов', '''class PasswordFactor:
    def verify(self, provided):
        return provided == 'demo-password' # Только модель интерфейса!

class PinFactor:
    def verify(self, provided):
        return provided == '1234' # Только учебная проверка!

factors = [PasswordFactor(), PinFactor()]
for factor, guess in zip(factors, ['bad', '1234']):
    print(type(factor).__name__, factor.verify(guess))''','PasswordFactor False\nPinFactor True','Одинаковый метод verify позволяет подменять реализацию. В реальной аутентификации простое равенство строк и открытые секреты не подходят.'),
('Декоратор: контроль доступа', '''from functools import wraps

def require_teacher(func):
    @wraps(func)
    def wrapper(role, *args, **kwargs):
        if role != 'teacher':
            return 'ACCESS_DENIED'
        return func(role, *args, **kwargs)
    return wrapper

@require_teacher
def edit_grade(role, value):
    return f'Изменение оценки: {value}'

print(edit_grade('student', 5))
print(edit_grade('teacher', 5))''','ACCESS_DENIED\nИзменение оценки: 5','В учебной модели проверяется роль; в настоящем сервисе сервер обязан также проверять полномочия на конкретный ресурс.')],
'quiz':[('Что относится к экземпляру класса?',['Общее имя класса','Конкретное состояние объекта','Текст документации'],1,'Экземпляр — конкретный объект со своим состоянием.'),('Даёт ли двойное подчёркивание защиту от злоумышленника?',['Да, это шифрование','Нет, применяется name mangling','Да, в любых версиях Python'],1,'Механизм меняет имя атрибута, но не вводит криптографические ограничения.'),('Какой подход упрощает поддержку?',['Разрешить прямое изменение любых полей','Объединить изменения состояния в методах','Удалить все методы'],1,'Методы позволяют централизованно проверять условия и сохранять инварианты.'),('Что делает декоратор?',['Выполняет дополнительную обёртку функции','Удаляет все атрибуты объекта','Компилирует код в C'],0,'Декоратор может добавлять общую логику без переписывания тела функции.')],
'refs':[('Python Classes','https://docs.python.org/3/tutorial/classes.html'),('functools','https://docs.python.org/3/library/functools.html'),('OWASP Password Storage','https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html')]},
8:{'name':'ООП, свойства и контроль доступа', 'kicker':'Инкапсуляция не равна полномочиям', 'lead':'@property, двойное подчёркивание, массовое присваивание и контроль изменений пользовательского профиля.',
'intro':('Пользователь отправляет серверу JSON с полями `display_name` и `role`. Если код без проверки копирует все поля в объект, ученик может попытаться назначить себе административную роль. Это типичный сценарий Mass Assignment.','Полномочия на операцию нужно проверять в доверенном серверном коде и применительно к конкретному объекту. Свойства Python помогают управлять атрибутами, но не заменяют авторизацию.'),
'concepts':[('@property','Доступ к вычисляемому или проверяемому значению как к атрибуту. Часто сочетается с setter, который проверяет диапазон допустимых значений.'),('Двойное подчёркивание','Имя `__token` преобразуется в `_ClassName__token`. Это защита от случайных конфликтов имён, а не шифрование и не авторизация.'),('Mass Assignment','Опасность возникает, когда поля запроса автоматически становятся полями модели без списка допустимых изменений.'),('Белый список полей','Система явно перечисляет поля, которые можно обновлять через конкретный endpoint. Роли и права обычно редактируются отдельным защищённым процессом.'),('Секреты в объектах','`repr()`, сериализация и логи могут случайно раскрыть пароль или токен. Не включайте чувствительные значения в публичные строковые представления.'),('Разделение ответственности','Модель отвечает за валидное состояние, сервис авторизации — за права субъекта, обработчик запроса — за формат входных данных.')],
'cases':[('Использование @property с валидацией', '''class UserScore:
    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new):
        if not isinstance(new, int) or not (0 <= new <= 100):
            raise ValueError('score must be 0..100')
        self._value = new

score = UserScore(75)
print(score.value)
try:
    score.value = 900
except ValueError as exc:
    print('Отклонено:', exc)''','75\nОтклонено: score must be 0..100','Setter защищает согласованность состояния при обычном использовании API, но не является контуром защиты от запуска произвольного Python-кода.'),
('Mass Assignment: безопасное обновление профиля', '''profile = {'display_name': 'Алексей', 'role': 'student'}
request = {'display_name': 'Александр', 'role': 'admin'}
EDITABLE = {'display_name'}

for key in EDITABLE & request.keys():
    profile[key] = request[key]
print(profile)''',"{'display_name': 'Александр', 'role': 'student'}",'Поле role проигнорировано. Настоящий сервер дополнительно проверяет тип, размер и содержимое каждого разрешённого поля, а также принадлежность профиля субъекту.'),
('Скрываем секрет из представления объекта', '''class ApiClient:
    def __init__(self, token):
        self._token = token

    def __repr__(self):
        return 'ApiClient(token=<redacted>)'

client = ApiClient('demo-token-not-real')
print(client)''','ApiClient(token=<redacted>)','Такое представление снижает риск случайного вывода секретов, но пароль всё равно не следует хранить в ненужных местах или логировать.')],
'quiz':[('Чем опасен Mass Assignment?',['Запрос может менять неразрешённые поля модели','Он всегда замедляет Python','Он полностью блокирует API'],0,'Поля вроде role не должны изменяться через открытое обновление профиля.'),('Является ли @property полноценной авторизацией?',['Да','Нет','Только на Python 3.12'],1,'Свойство управляет доступом к атрибуту через API объекта; серверные полномочия проверяются отдельно.'),('Что должно попасть в системный лог?',['Полный токен','Пароль пользователя','Обезличенная диагностическая информация'],2,'Секретные значения нельзя записывать в журналы.'),('Как защищать обновление профиля?',['Копировать все поля без проверки','Проверять разрешённые поля и полномочия','Доверять скрытым полям формы'],1,'Белый список и серверная проверка прав обязательны.')],
'refs':[('Python property','https://docs.python.org/3/library/functions.html#property'),('OWASP Mass Assignment','https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'),('OWASP Authorization','https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html')]},
9:{'name':'Классы, роли и инкапсуляция в кибербезопасности','kicker':'Аутентификация ≠ авторизация','lead':'Моделируем пользователя, ресурс и правило доступа. Учимся не путать скрытые элементы интерфейса с реальной защитой.',
'intro':('Ученик видит кнопку «Просмотр оценок», а учитель — «Изменить оценку». Если сервер ориентируется только на видимость кнопки, прямой HTTP-запрос может обойти это ограничение. Нам нужны проверяемые правила.','Для полноценной авторизации мало роли: нужно учитывать конкретного пользователя, действие, объект, контекст и принцип минимальных привилегий.'),
'concepts':[('Аутентификация','Отвечает на вопрос «кто это?» — проверяет учётные данные или факторы входа.'),('Авторизация','Отвечает на вопрос «что этому субъекту разрешено сделать?» — проверяется при каждой защищаемой операции.'),('RBAC','Ролевая модель связывает группы разрешений с ролями. Хорошо подходит для учебных примеров, но требует детализации ресурсов.'),('IDOR / BOLA','Если изменение идентификатора ресурса открывает чужие данные, отсутствует объектная проверка доступа.'),('Принцип минимальных привилегий','Пользователь и сервис получают только те права, которые необходимы для выполнения задач.'),('Разделение ответственности','Класс Resource хранит состояние объекта, отдельный policy проверяет доступ, сервис выполняет действие только после проверки.')],
'cases':[('Политика ролей: разрешённые действия', '''PERMISSIONS = {
    'student': {'view_own'},
    'teacher': {'view_own', 'edit_assigned'},
    'admin': {'view_own', 'manage_users'},
}

def allowed(role, action):
    return action in PERMISSIONS.get(role, set())

for role in ('student', 'teacher', 'admin'):
    print(role, allowed(role, 'edit_assigned'))''','student False\nteacher True\nadmin False','Политика по умолчанию запрещает действие. В настоящей системе учитель также должен иметь право изменять конкретный класс или журнал.'),
('Проверка владельца ресурса', '''def can_view_record(user_id, record):
    return user_id == record['owner_id']

record = {'owner_id': 17, 'grade': 5}
print(can_view_record(17, record))
print(can_view_record(19, record))''','True\nFalse','Смена ID в запросе не должна позволять читать чужие записи. На сервере всегда проверяем владельца и контекст.'),
('Безопасный отказ и события аудита', '''def edit_grade(role, scope_allowed, grade):
    if role != 'teacher' or not scope_allowed:
        return {'status': 'DENIED', 'grade': None}
    return {'status': 'OK', 'grade': grade}

print(edit_grade('student', True, 5)['status'])
print(edit_grade('teacher', False, 5)['status'])
print(edit_grade('teacher', True, 5)['status'])''','DENIED\nDENIED\nOK','Учебная модель показывает две независимые проверки — роль и область полномочий. Реальная модель сложнее и должна тестироваться на негативных сценариях.')],
'quiz':[('Какой вопрос решает авторизация?',['Кто пользователь?','Что пользователю разрешено?','Какой у него браузер?'],1,'Аутентификация идентифицирует, авторизация проверяет разрешения.'),('Безопасна ли скрытая кнопка?',['Нет, сервер должен проверять права','Да, её невозможно обойти','Да, если цвет кнопки серый'],0,'HTTP-запрос к endpoint можно отправить без интерфейса.'),('Что такое доступ к чужой записи по изменённому ID?',['Базовая функция интерфейса','IDOR/BOLA','Шифрование'],1,'Уязвимость возникает при недостаточной проверке доступа к конкретному объекту.'),('Какой принцип надёжнее?',['Разрешить всё неизвестное','Проверить доступ после изменения','Запретить по умолчанию и проверить перед действием'],2,'Fail-closed и проверка в доверенном контуре — правильная отправная точка.')],
'refs':[('OWASP Authorization','https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'),('OWASP API Security Top 10','https://owasp.org/API-Security/'),('Python Classes','https://docs.python.org/3/tutorial/classes.html')]}}

CSS='''
:root{--bg:#061723;--p:#0d2839;--line:#34576b;--text:#ebf8fa;--muted:#a8c6d1;--cyan:#79d3cd;--gold:#ffcf90}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;line-height:1.67}a{color:var(--cyan)}button{cursor:pointer;font:inherit}.wide{max-width:1150px;margin:auto;padding:0 20px}.hero{padding:70px 0;background:radial-gradient(circle at 78% 10%,#1b5961,#102c3c 52%,#071925);border-bottom:1px solid #316073}.kicker{letter-spacing:.15em;text-transform:uppercase;color:#a0dfd6;font-size:12px;font-weight:750}.hero h1{font-size:clamp(37px,5.5vw,66px);line-height:1.05;max-width:950px;letter-spacing:-.04em;margin:15px 0}.hero p{font-size:19px;color:#c8e2e7;max-width:830px}.pills{display:flex;gap:10px;flex-wrap:wrap}.pill{border-radius:99px;padding:6px 12px;border:1px solid #4c8191;font-size:12px;background:#183b49}.sections{padding:44px 0 90px}section{margin:35px 0 60px}section h2{font-size:30px;letter-spacing:-.025em;margin:0 0 13px}.lead{color:var(--muted);font-size:17px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.card{border:1px solid var(--line);border-radius:19px;padding:23px;background:linear-gradient(145deg,#123247,#092330)}.card h3{margin:0 0 12px;color:#d4f4eb}.card p{margin:0;color:#bed7df}.highlight{border-left:4px solid var(--gold);padding:17px 22px;border-radius:8px;background:#132c3c;color:#e4e0d7}.diagram{overflow:auto;border:1px solid var(--line);border-radius:18px;background:#0a2434;padding:16px}.diagram svg{display:block;width:100%;min-width:580px;max-height:230px}.labs{display:grid;gap:23px}.lab{background:#0e2636;border:1px solid var(--line);border-radius:20px;overflow:hidden}.lab header{padding:22px 23px;display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}.lab h3{font-size:20px;margin:0}.copy{background:#236c76;color:#eefcf9;border:1px solid #4abbb4;border-radius:9px;padding:10px 15px}.copy:hover{background:#33858c}.lab pre{margin:0;padding:24px;overflow:auto;color:#d8edf4;background:#081a27;line-height:1.58;font-size:14px}.explain{padding:18px 23px;color:#c8dfe6}.expected{background:#174639;color:#a7edce;padding:10px 23px;font-family:monospace;white-space:pre-wrap}.question{border:1px solid #345a6b;border-radius:16px;padding:24px;margin:14px 0;background:#102e3f}.question h3{margin-top:0;font-size:17px}.answers{display:grid;gap:9px}.answers button{border:1px solid #3c6377;border-radius:10px;background:#17394b;color:white;text-align:left;padding:11px 13px}.answers button.good{background:#205c45;border-color:#5abb87}.answers button.bad{background:#663744;border-color:#dc8290}.feedback{font-size:14px;color:#b4d9e2;min-height:22px;margin-top:10px}.ref{display:flex;gap:12px;flex-wrap:wrap}.ref a{background:#14384b;border:1px solid #406477;border-radius:10px;text-decoration:none;padding:10px 13px;font-size:14px}footer{padding:27px;background:#0b2837;border-top:1px solid var(--line);color:#a6c7d1;font-size:13px}footer a{margin-right:18px}code{color:#bce8d9}button:focus-visible,a:focus-visible{outline:3px solid #cce79d;outline-offset:3px}@media(max-width:760px){.grid{grid-template-columns:1fr}.hero{padding:44px 0}.wide{padding:0 15px}.lab pre{padding:16px}.card{padding:19px}}
'''

def diagram(n):
 steps=[('Вход','Учётная запись'),('Правило','Проверка'),('Объект','Состояние'),('Решение','Разрешить / отказать')]
 out=['<svg viewBox="0 0 940 180" role="img" aria-label="Схема проверки безопасности"><defs><linearGradient id="da" x1="0" x2="1"><stop stop-color="#1c4c60"/><stop offset="1" stop-color="#174b4e"/></linearGradient></defs>']
 for i,(a,b) in enumerate(steps):
  x=14+i*233
  out+=[f'<rect x="{x}" y="30" width="209" height="115" rx="15" fill="url(#da)" stroke="#65b1a9"/><text x="{x+15}" y="65" fill="#a8e0d3" font-size="15" font-weight="bold">0{i+1}. {escape(a)}</text><text x="{x+15}" y="99" fill="#eef4f5" font-size="15">{escape(b)}</text>']
  if i<3:out +=[f'<path d="M{x+209} 86 H{x+228}" stroke="#9de1cc" stroke-width="3"/><path d="m{x+223} 81 5 5-5 5" stroke="#9de1cc" fill="none"/>']
 out.append('</svg>');return ''.join(out)

def build(n):
 d=DATA[n]
 concepts=''.join(f'<div class="card"><h3>{escape(t)}</h3><p>{escape(desc)}</p></div>' for t,desc in d['concepts'])
 labs=''
 for i,(title,code,expected,exp) in enumerate(d['cases'],1):
  labs+=f'<article class="lab"><header><h3>{i:02d}. {escape(title)}</h3><button class="copy" data-copy="code{n}-{i}">⧉ Копировать Python</button></header><pre><code id="code{n}-{i}">{escape(code)}</code></pre><div class="expected">{escape(expected)}</div><div class="explain"><b>Разбор.</b> {escape(exp)}</div></article>'
 questions=''
 for i,(q,opts,correct,why) in enumerate(d['quiz'],1):
  bs=''.join(f'<button type="button" data-answer="{j}" data-correct="{correct}" data-why="{escape(why,quote=True)}">{escape(ans)}</button>' for j,ans in enumerate(opts))
  questions+=f'<div class="question"><h3>{i}. {escape(q)}</h3><div class="answers">{bs}</div><div class="feedback" role="status">Выберите вариант и проверьте решение.</div></div>'
 refs=''.join(f'<a href="{url}" target="_blank" rel="noopener noreferrer">{escape(t)} ↗</a>' for t,url in d['refs'])
 html=f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Урок {n} · {escape(d['name'])} | Код будущего</title><meta name="description" content="Интерактивное занятие по Python и информационной безопасности: {escape(d['lead'],quote=True)}"><style>{CSS}</style></head><body>
<div class="hero"><div class="wide"><div class="kicker">Код будущего • Python × кибербезопасность • занятие {n}</div><h1>{escape(d['name'])}</h1><p>{escape(d['lead'])}</p><div class="pills"><span class="pill">Теория и схемы</span><span class="pill">3 лаборатории</span><span class="pill">4 вопроса с объяснениями</span><span class="pill">Код копируется</span></div></div></div>
<main class="wide sections"><section><div class="kicker">Ситуация • портал «Сигнал»</div><h2>{escape(d['kicker'])}</h2><div class="grid"><div class="card"><h3>Инженерная задача</h3><p>{escape(d['intro'][0])}</p></div><div class="card"><h3>Граница модели</h3><p>{escape(d['intro'][1])}</p></div></div><p class="highlight">Важно: любой пример в курсе использует искусственные данные. Действия с настоящими сервисами допустимы только при наличии полномочий.</p></section>
<section><h2>Как взаимодействуют части системы</h2><p class="lead">Вместо магического «объект защищён» разбираем последовательность: кто выполняет действие, какая проверка применяется, что происходит со значением и что фиксируем в результате.</p><div class="diagram">{diagram(n)}</div></section>
<section><h2>Понятия и пояснения</h2><div class="grid">{concepts}</div></section>
<section><h2>Практика Python: запусти и объясни</h2><p class="lead">Каждый фрагмент запускается в Python 3 без сторонних зависимостей. Попробуйте изменить входные данные и предсказать результат до запуска.</p><div class="labs">{labs}</div></section>
<section><h2>Контрольные вопросы</h2><p class="lead">Нажмите на вариант и прочитайте объяснение. Можно пересматривать ответы без ограничения.</p>{questions}</section>
<section><h2>Применение в собственном проекте</h2><div class="grid"><div class="card"><h3>Проверь архитектуру</h3><p>Выпишите защищаемый актив, субъект, действие и место, где проверяются полномочия. Разделите корректность состояния объекта и безопасность операции.</p></div><div class="card"><h3>Негативный тест</h3><p>Представьте пользователя с минимальными правами. Каким прямым вызовом он мог бы обойти клиентский интерфейс? Добавьте проверку в доверенную часть системы.</p></div></div></section>
<section><h2>Достоверные источники</h2><div class="ref">{refs}</div></section></main>
<footer><div class="wide">Код будущего · Урок {n} · Безопасное программирование на Python. <a href="index.html">Оглавление</a><a href="lesson_{n-1}.html">Предыдущий</a><a href="lesson_{n+1}.html">Следующий</a></div></footer>
<script>(function(){{document.querySelectorAll('.copy').forEach(function(b){{b.addEventListener('click',function(){{var code=document.getElementById(b.dataset.copy).textContent;var fallback=function(){{var el=document.createElement('textarea');el.value=code;document.body.append(el);el.select();document.execCommand('copy');el.remove();b.textContent='✓ Скопировано';}};if(navigator.clipboard&&window.isSecureContext){{navigator.clipboard.writeText(code).then(function(){{b.textContent='✓ Скопировано'}}).catch(fallback)}}else fallback();setTimeout(function(){{b.textContent='⧉ Копировать Python'}},1800)}})}});document.querySelectorAll('.answers').forEach(function(g){{g.querySelectorAll('button').forEach(function(b){{b.addEventListener('click',function(){{g.querySelectorAll('button').forEach(function(x){{x.classList.remove('good','bad');if(x.dataset.answer===x.dataset.correct)x.classList.add('good')}});if(b.dataset.answer!==b.dataset.correct)b.classList.add('bad');g.parentElement.querySelector('.feedback').textContent=b.dataset.why}})}})}})}})();</script></body></html>'''
 return html

if __name__=='__main__':
 for n in (7,8,9):
  p=ROOT/f'lesson_{n}.html'
  if p.exists(): continue
  p.write_text(build(n),encoding='utf-8')
  print(p.name,p.stat().st_size)
