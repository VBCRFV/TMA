bot_token = '1234567890:AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz'

# Функия расчёта HMAC-SHA-256 строки data_check_string, пердаваемой в поле Telegram.WebApp.initData.
def HMAC_SHA256(msg: (str,bytes,bytearray) = None,
                key: (str,bytes,bytearray) = None,
                ret: str = 'object') -> str:
    '''
    :param msg: хешируемый текст, поддерживаемые типы (str,bytes,bytearray).
    :param key: секретный ключ, поддерживаемые типы (str,bytes,bytearray).
    :param ret: тип возвращаемого значения, возможные варианты ('byte','hex') или возвращается объект hmac.
    :return: строка содержащая результат MAC-SHA-256.
    '''
    # DOC - https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
    import hmac, hashlib
    msg = msg.encode() if type(msg) == str else msg
    key = key.encode() if type(key) == str else key
    hashing_object = hmac.new(key, msg=msg, digestmod=hashlib.sha256)
    if ret == 'byte':
        return hashing_object.digest()
    elif ret == 'hex':
        return hashing_object.hexdigest()
    return hashing_object

# Пакрсинг Telegram.WebApp.initData и расчёт HMAC-SHA-256.
def Validating_initData(bot_token: str,
                        initData: str,
                        debug: bool = False) -> bool:
    '''
    :param bot_token: идентификатор, полученный от @BotFather. (без "bot_").
    :param initData: Telegram.WebApp.initData (https://core.telegram.org/bots/webapps#webappinitdata).
    :param debug: вывод отладочных сообщений, возможные значения (True,False).
    :return: возвращает результат сравнения Telegram.WebApp.initData.hesh и вычисленного.
    '''
    from urllib.parse import parse_qsl as pqsl
    if debug: print("initData:", initData)
    # Преобразуем строку в словарь.
    initData_pqsl = dict(pqsl(initData))
    if debug: print('initData_pqsl:',initData_pqsl)
    # Удаляем из словоря hash.
    hash_ = initData_pqsl.pop('hash')
    # Сортируем словарь по ключу.
    initData_sorted = dict(sorted(initData_pqsl.items()))
    if debug: print('initData_sorted:',initData_sorted)
    # Формируем data_check_string.
    initData_list = [f"{key}={initData_sorted[key]}" for key in initData_sorted]
    if debug: print('initData_list:',initData_list)
    data_check_string = '\n'.join(initData_list)
    # Хешируем secret_key.
    secret_key = HMAC_SHA256(msg=bot_token,key="WebAppData",ret='byte')
    # Хешируем initData hash.
    hash_verified_ = HMAC_SHA256(msg=data_check_string,key=secret_key,ret='hex')
    if debug:
        print(hash_verified_)
        print(hash_)
        print('Validating:',hash_verified_==hash_)
    return hash_verified_==hash_
