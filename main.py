#!/usr/bin/python3
import hashlib
import json
import logging
import re
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import urlparse
from urllib.parse import parse_qs

import requests

# Кэш slnet токенов (живут 24 часа). Ключ - slid токен (живёт год)
slnet_token_cache = {}

http_server_port = 2307


class HttpGetHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path.startswith("/application/slidToken"):
            parsed_url = urlparse(self.path)
            app_id = parse_qs(parsed_url.query)['appId'][0]
            app_secret = parse_qs(parsed_url.query)['appSecret'][0]
            login = parse_qs(parsed_url.query)['login'][0]
            password = parse_qs(parsed_url.query)['password'][0]
            if 'smsCode' in parse_qs(parsed_url.query):
                sms_code = parse_qs(parsed_url.query)['smsCode'][0]
            else:
                sms_code = None
            login_response = get_login_info(app_id, app_secret, login, password, sms_code)
            if "state" in login_response:
                response = {"userId": login_response['desc']['id'], "slidToken": login_response['desc']['user_token']}
                json_response(self, response)
            else:
                json_response(self, login_response)
        elif self.path.startswith("/device/"):
            device_id = re.search("device/(.*?)/data", self.path).group(1)
            parsed_url = urlparse(self.path)
            slid_token = parse_qs(parsed_url.query)['slidToken'][0]
            device_info = get_device_info(device_id, slid_token).get("data")
            json_response(self, device_info)
        elif self.path.startswith("/user/"):
            user_id = re.search("user/(.*?)/devices", self.path).group(1)
            parsed_url = urlparse(self.path)
            slid_token = parse_qs(parsed_url.query)['slidToken'][0]
            device_info = get_user_info(user_id, slid_token).get("user_data").get("devices")
            devices = []
            for device_info in device_info:
                device = {"alias": device_info["alias"], "device_id": device_info["device_id"]}
                devices.append(device)
            json_response(self, devices)


def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
    server_address = ('', http_server_port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


def get_app_code(app_id, app_secret):
    """
    Получение кода приложения для дальнейшего получения токена.
    Идентификатор приложения и пароль выдаются контактным лицом СтарЛайн.
    Срок годности кода приложения 1 час.
    :param app_id: Идентификатор приложения
    :param app_secret: Пароль приложения
    :return: Код, необходимый для получения токена приложения
    """
    url = 'https://id.starline.ru/apiV3/application/getCode/'
    log('execute request: {}'.format(url))

    payload = {
        'appId': app_id,
        'secret': hashlib.md5(app_secret.encode('utf-8')).hexdigest()
    }
    r = requests.get(url, params=payload)
    response = r.json()
    log('payload : {}'.format(payload))
    log('response info: {}'.format(r))
    log('response data: {}'.format(response))
    if int(response['state']) == 1:
        app_code = response['desc']['code']
        log('Application code: {}'.format(app_code))
        return app_code
    raise Exception(response)


def get_app_token(app_id, app_secret, app_code):
    """
    Получение токена приложения для дальнейшей авторизации.
    Время жизни токена приложения - 4 часа.
    Идентификатор приложения и пароль можно получить на my.starline.ru.
    :param app_id: Идентификатор приложения
    :param app_secret: Пароль приложения
    :param app_code: Код приложения
    :return: Токен приложения
    """
    url = 'https://id.starline.ru/apiV3/application/getToken/'
    log('execute request: {}'.format(url))
    payload = {
        'appId': app_id,
        'secret': hashlib.md5((app_secret + app_code).encode('utf-8')).hexdigest()
    }
    r = requests.get(url, params=payload)
    response = r.json()
    log('payload: {}'.format(payload))
    log('response info: {}'.format(r))
    log('response data: {}'.format(response))
    if int(response['state']) == 1:
        app_token = response['desc']['token']
        log('Application token: {}'.format(app_token))
        return app_token
    raise Exception(response)


def get_slid_user_token(app_token, user_login, user_password, sms_code):
    """
     Аутентификация пользователя по логину и паролю.
     Неверные данные авторизации или слишком частое выполнение запроса авторизации с одного
     ip-адреса может привести к запросу капчи.
     Для того, чтобы сервер SLID корректно обрабатывал клиентский IP,
     необходимо проксировать его в параметре user_ip.
     В противном случае все запросы авторизации будут фиксироваться для IP-адреса сервера приложения, что приведет к час
     тому требованию капчи.
    :param sms_code:
    :param app_token: Токен приложения
    :param user_login: Логин пользователя
    :param user_password: Пароль пользователя
    :return: Токен, необходимый для работы с данными пользователя. Данный токен потребуется для авторизации на StarLine
    API сервере.
    """
    url = 'https://id.starline.ru/apiV3/user/login/'
    log('execute request: {}'.format(url))
    payload = {
        'token': app_token
    }
    data = {"login": user_login, "pass": hashlib.sha1(user_password.encode('utf-8')).hexdigest()}
    if sms_code is not None:
        data["smsCode"] = sms_code

    r = requests.post(url, params=payload, data=data)
    response = r.json()
    log('payload : {}'.format(payload))
    log('response info: {}'.format(r))
    log('response data: {}'.format(response))
    if int(response['state']) == 2:  # Need confirmation
        return "add smsCode to request"
    elif int(response['state']) == 1:
        return response
    elif int(response['state']) == 0:
        sms_code = input()
        data["smsCode"] = sms_code
        r = requests.post(url, params=payload, data=data)
        response = r.json()
        raise Exception(response)
    raise Exception(response)


# получить slid_token. Действителен 1 год
def get_login_info(app_id, app_secret, login, password, sms_code):
    # Получим код приложения
    app_code = get_app_code(app_id, app_secret)

    # Получим токен приложения. Действителен 4 часа
    app_token = get_app_token(app_id, app_secret, app_code)

    # Получим slid-токен юзера. Действителен 1 год
    return get_slid_user_token(app_token, login, password, sms_code)


def get_slnet_token(slid_token):
    return get_auth(slid_token).cookies["slnet"]


def get_user_id(slid_token):
    return get_auth(slid_token).json().response["user_id"]


def get_auth(slid_token):
    url = 'https://developer.starline.ru/json/v2/auth.slid'
    data = {
        'slid_token': slid_token
    }
    return requests.post(url, json=data)


def get_cached_slnet_token(slid_token):
    slnet_token = slnet_token_cache.get(slid_token)
    if slnet_token is None:
        slnet_token = get_slnet_token(slid_token)
        slnet_token_cache[slid_token] = slnet_token
    return slnet_token


def send_authed_request(url, slid_token):
    response = requests.get(url, headers=cookie(slid_token)).json()
    if response["code"] == 401:
        slnet_token = get_slnet_token(slid_token)
        slnet_token_cache[slid_token] = slnet_token
        response = requests.get(url, headers=cookie(slid_token)).json()
    return response


def get_user_info(user_id, slid_token):
    url = "https://developer.starline.ru/json/v3/user/{}/data".format(user_id)
    return send_authed_request(url, slid_token)


def get_device_info(device_id, slid_token):
    url = "https://developer.starline.ru/json/v3/device/{}/data".format(device_id)
    return send_authed_request(url, slid_token)


def log(message):
    logging.warning(message)


def cookie(slid_token):
    slnet_token = get_cached_slnet_token(slid_token)
    return {"Cookie": "slnet=" + slnet_token}


def json_response(response, data):
    response.send_response(200)
    response.send_header("Content-type", "application/json")
    response.end_headers()
    response.wfile.write(str.encode(json.dumps(data)))


log("Started http server on port " + str(http_server_port))
run(handler_class=HttpGetHandler)
