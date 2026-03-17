#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Профессиональный обработчик HTTP-запросов
Для работы с защищенными сайтами в этичных целях
"""

import time
import random
import ssl
import warnings
from typing import Optional, List, Dict
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style

warnings.filterwarnings('ignore', category=InsecureRequestWarning)


class RequestHandler:
    """Обработчик запросов с обходом базовых защит"""

    # Реалистичные User-Agent строки (последние версии браузеров)
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    ]

    # Реалистичные заголовки браузера
    DEFAULT_HEADERS = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    }

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.session = self._create_session()
        self.request_count = 0
        self.last_request_time = 0
        self.proxy_list = self._load_proxies()
        self.current_proxy_index = 0

    def _create_session(self) -> requests.Session:
        session = requests.Session()

        # SSL настройки для тестов
        session.verify = self.config.get('ssl_verify', False)
        if not session.verify:
            # Повторно подавляем предупреждения для этой сессии
            warnings.filterwarnings('ignore', category=InsecureRequestWarning)

        # Таймауты
        session.timeout = self.config.get('timeout', 15)

        # Адаптер с настройками пула соединений
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.config.get('pool_connections', 10),
            pool_maxsize=self.config.get('pool_maxsize', 20),
            max_retries=0  # Мы обрабатываем повторения вручную
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session

    def _load_proxies(self) -> List[str]:
        proxies_file = self.config.get('proxies_file', 'proxies.txt')
        proxies = []

        try:
            with open(proxies_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
        except FileNotFoundError:
            pass  # Прокси не обязательны

        return proxies

    def _get_random_user_agent(self) -> str:
        """Получение случайного User-Agent"""
        # Загрузка из файла если есть
        ua_file = self.config.get('user_agents_file', 'user_agents.txt')
        try:
            with open(ua_file, 'r', encoding='utf-8') as f:
                agents = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                if agents:
                    return random.choice(agents)
        except:
            pass

        return random.choice(self.USER_AGENTS)

    def _get_next_proxy(self) -> Optional[Dict]:
        if not self.proxy_list:
            return None

        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)

        # Парсинг прокси
        if '://' in proxy:
            return {'http': proxy, 'https': proxy}
        return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}

    def _apply_rate_limit(self):
        """Применение rate limiting"""
        min_delay = self.config.get('min_request_delay', 1.0)
        max_delay = self.config.get('max_request_delay', 3.0)

        if self.last_request_time > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < min_delay:
                sleep_time = min_delay - elapsed + random.uniform(0, max_delay - min_delay)
                time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _randomize_headers(self, base_headers: Dict = None) -> Dict:
        """Добавление случайных элементов в заголовки для снижения детектирования"""
        headers = {**self.DEFAULT_HEADERS, **(base_headers or {})}

        # Добавление случайных, но реалистичных заголовков
        optional_headers = {
            'DNT': random.choice(['1', '0']),
            'Sec-Ch-Ua': f'"Not_A Brand";v="{random.randint(1, 99)}", "Chromium";v="{random.randint(100, 130)}"',
            'Sec-Ch-Ua-Mobile': random.choice(['?0', '?1']),
            'Sec-Ch-Ua-Platform': random.choice(['"Windows"', '"macOS"', '"Linux"']),
        }

        # Добавляем 1-3 случайных заголовка
        for key, value in random.sample(list(optional_headers.items()),
                                        k=random.randint(1, min(3, len(optional_headers)))):
            headers[key] = value

        return headers

    def _handle_response(self, response: requests.Response, url: str) -> Optional[requests.Response]:
        # Статусы, указывающие на блокировку или rate limit
        block_statuses = [403, 429, 503, 529, 530]

        if response.status_code in block_statuses:
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    wait_time = int(retry_after)
                except ValueError:
                    wait_time = 5
            else:
                wait_time = min(30, 2 ** self.request_count)

            return {'blocked': True, 'wait_time': wait_time, 'status': response.status_code}

        # Проверка на возможные ловушки для ботов
        if 'captcha' in response.text.lower() or 'access denied' in response.text.lower():
            return {'blocked': True, 'wait_time': 10, 'reason': 'captcha_detected'}

        return response

    def request(self, url: str, method: str = 'GET',
                headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """
        Метод запроса с обработкой защит

        Returns:
            requests.Response или None при ошибке
        """
        max_retries = self.config.get('max_retries', 3)
        base_delay = self.config.get('retry_base_delay', 2.0)

        for attempt in range(max_retries):
            try:
                self._apply_rate_limit()

                final_headers = self._randomize_headers(headers)
                final_headers['User-Agent'] = self._get_random_user_agent()

                proxies = None
                if self.config.get('use_proxy', False) and self.proxy_list:
                    proxies = self._get_next_proxy()

                self.request_count += 1

                response = self.session.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    proxies=proxies,
                    allow_redirects=True,
                    **kwargs
                )

                result = self._handle_response(response, url)

                if isinstance(result, dict) and result.get('blocked'):
                    wait_time = result.get('wait_time', base_delay)
                    reason = result.get('reason', f'HTTP {result.get("status")}')

                    if attempt < max_retries - 1:
                        time.sleep(wait_time)
                        continue
                    else:
                        return None

                return response

            except requests.exceptions.ConnectionError as e:
                if 'Connection aborted' in str(e) or 'Connection reset' in str(e):
                    # Сервер сбросил соединение - возможно, защита сработала
                    if attempt < max_retries - 1:
                        wait = base_delay * (2 ** attempt) + random.uniform(0, 2)
                        time.sleep(wait)
                        continue
                return None

            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (attempt + 1))
                    continue
                return None

            except requests.exceptions.SSLError:
                # Пробуем отключить проверку SSL для этого запроса
                if kwargs.get('verify', True):
                    kwargs['verify'] = False
                    continue
                return None

            except Exception as e:
                # Логирование для отладки
                if self.config.get('debug', False):
                    print(f"{Fore.YELLOW}[DEBUG] Request error: {e}{Style.RESET_ALL}")
                if attempt < max_retries - 1:
                    time.sleep(base_delay)
                    continue
                return None

        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """GET запрос"""
        return self.request(url, 'GET', **kwargs)

    def post(self, url: str, data: Dict = None, json: Dict = None, **kwargs) -> Optional[requests.Response]:
        """POST запрос"""
        return self.request(url, 'POST', data=data, json=json, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """OPTIONS запрос"""
        return self.request(url, 'OPTIONS', **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """HEAD запрос"""
        return self.request(url, 'HEAD', **kwargs)

    def close(self):
        """Закрытие сессии"""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()