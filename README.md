# Кутьин З.С. Программа и база данных для хранения сведений о событияъ авторизации пользователей ОС семейства Линукс
## Запуск приложения
1. Установите python 3.11+ с официальной страницы [ссылка на python](https://www.python.org/)
2. Скачайте проект с GitHub.
3. В терминале перейдите в папку с проектом и разверните виртуальное окружение venv:
  - REDHAT-подобная система:
    - sudo dnf install -y python3-venv
    - sudo dnf install -y build-essential libssl-dev libffi-dev python3-dev
    - python -m venv venv
    - source venv/bin/activate
  - Debian-подобная система:
    - sudo apt install -y python3-venv
    - sudo apt install -y build-essential libssl-dev libffi-dev python3-dev
    - python -m venv venv
    - source venv/bin/activate
4. Установите необходимые библиотеки из req.txt
  - cat req.txt | xargs -n 1 pip install
5. Запустите приложение из корневой директории проекта на вашем ПК: - python3 .\main.py
