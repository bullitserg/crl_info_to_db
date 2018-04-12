import re
import requests
import argparse
import logger_module
import progressbar
from os.path import normpath, join
from os import remove
from hashlib import md5
from ets.ets_certificate_lib import Crl
from ets.ets_certmanager_logs_parser import get_crl_point_file
from datetime import datetime, timedelta
from OpenSSL.crypto import Error as Crypto_error
from ets.ets_mysql_lib import MysqlConnection as mc, NULL, value_former
from queries import *
from config import *


PROGNAME = 'Crl data downloader'
DESCRIPTION = '''Скрипт для импортирования данных из списка url и сохранения данных по ним в базу данных'''
VERSION = '1.0'
AUTHOR = 'Belim S.'
RELEASE_DATE = '2018-04-05'

u_server_list = []

tmp_dir = normpath(tmp_dir)
cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
cn.connect()


def show_version():
    print(PROGNAME, VERSION, '\n', DESCRIPTION, '\nAuthor:', AUTHOR, '\nRelease date:', RELEASE_DATE)


# обработчик параметров командной строки
def create_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-v', '--version', action='store_true',
                        help="Показать версию программы")

    parser.add_argument('-u', '--update', action='store_true',
                        help='''Обновить записи в базе данных.
                        Аргументы:
                        --server - обновить для указанного сервера (необязательный)''')

    parser.add_argument('-f', '--fast_update_by_auth_key', action='store_true',
                        help='''Быстрое обновление данных по auth_key.
                        Аргументы:
                        --auth_key - идентификатор (обязательный);
                        --server - обновить для указанного сервера (необязательный)''')

    parser.add_argument('-r', '--remove', action='store_true',
                        help='''Удалить устаревшие записи.
                        Аргументы:
                        --server - удалить для указанного сервера (необязательный);
                        --days - за указанное количество дней (по умолчанию 10, необязательный)''')

    parser.add_argument('-c', '--check_revoke_status', action='store_true',
                        help='''Проверка статуса отзыва для сертификата.
                        Аргументы:
                        --certificate_number - номер сертификата (обязательный).
                        Типы проверки:
                        --url - проверяет по конкретному url, всегда подгружается свежий crl;
                        --auth_key - проверка по всем свежим crl, загруженным по ссылкам,
                        соответствующим указанному auth_key;
                        --hash - проверка по crl файлу, хранящемуся в БД с указанным md5-хэшем''')

    parser.add_argument('-s', '--server', type=int, choices=d_server_list,
                        help="Установить номер сервера")

    parser.add_argument('-k', '--auth_key', type=str,
                        help="Установить auth_key")

    parser.add_argument('-l', '--url', type=str,
                        help="Установить url")

    parser.add_argument('-a', '--hash', type=str,
                        help="Установить md5-хеш")

    parser.add_argument('-n', '--certificate_number', type=str,
                        help="Установить номер сертификата")

    parser.add_argument('-d', '--days', type=int,
                        help="Установить количество дней")

    return parser


# функция проверяет количество возвращенных id и при необходимости выводит сообщение и завершает программу
def return_value_with_len_check(iter_data, value_text):
    iter_data_len = len(iter_data)
    if iter_data_len == 1:
        return iter_data[0][0]
    elif iter_data_len == 0:
        print('%s не найден' % value_text)
    elif iter_data_len > 0:
        print('Найдено несколько значений %s: %s' % (value_text, iter_data))
    exit(1)


def get_and_parse_crl_url_file(server):
    """Функция для получения url и"""
    get_crl_point_file(server, out_dir=tmp_dir)
    crl_urls_f = join(tmp_dir, 'crl_points_%s.txt' % server)

    with open(crl_urls_f, mode='r', encoding='utf8') as crl_urls_o:
        crl_urls_r = crl_urls_o.read()

    crl_urls = re.findall(r'http:.*?\.crl', crl_urls_r)

    return crl_urls


def crl_updater(server, url):

    info_data = {'server': value_former(server), 'url': value_former(url)}

    try:
        # скачиваем Crl
        response = requests.get(url, timeout=(1, None))
        if response.status_code == 200:
            info_data['status'] = value_former('success')

            # указываем дату последнего изменения страницы
            last_modified = response.headers.get('Last-Modified', None)
            if last_modified:
                info_data['lastUrlModificationDatetime'] = value_former(
                    datetime.strptime(last_modified,
                                      '%a, %d %b %Y %H:%M:%S GMT') +
                    timedelta(hours=timezone))
            else:
                info_data['lastUrlModificationDatetime'] = NULL

            # записываем данные в файл
            crl_data = response.content
            m = md5()
            m.update(crl_data)
            crl_file_hash = m.hexdigest()

            info_data['crlFileHash'] = value_former(crl_file_hash)

            crl_name = crl_file_hash + '_' + str(datetime.now().timestamp()) + '.crl'
            info_data['crlFileName'] = value_former(crl_name)

            crl_name_with_link = join(tmp_dir, crl_name)
            info_data['crlFileLocation'] = value_former(crl_name_with_link.replace('\\', '/'))

            with open(crl_name_with_link, mode='wb') as crl_out_f:
                crl_out_f.write(crl_data)

            crl = Crl(crl_name_with_link, timezone=timezone)

            info_data['crl_CN'] = value_former(crl.get_crl_issuer()['CN'])
            info_data['crl_O'] = value_former(crl.get_crl_issuer()['O'])

            crl_info = crl.compile_info_v5()
            info_data['subjKeyId'] = value_former(crl_info.get_crl_authkey())
            info_data['thisUpdateDatetime'] = value_former(crl_info.get_this_update_datetime())
            info_data['nextUpdateDatetime'] = value_former(crl_info.get_next_update_datetime())

        else:
            info_data['status'] = value_former('html_status_error')
    except requests.exceptions.RequestException:
        info_data['status'] = value_former('request_error')
    except Crypto_error:
        info_data['status'] = value_former('crypto_error')
    except ImportError:
        info_data['status'] = value_former('file_size_error')

    # забиваем info_data пустыми данными NULL, в том числе, если там None или что то подобное, возвращающее False
    for key in ('lastUrlModificationDatetime', 'crl_CN', 'crl_O', 'subjKeyId',
                'thisUpdateDatetime', 'nextUpdateDatetime', 'crlFileHash', 'crlFileName', 'crlFileLocation'):
        value = info_data.get(key, False)
        if (not value) or (value == "'False'") or (value == "'None'"):
            info_data[key] = NULL

    cn.execute_query(insert_crl_info_query % info_data)


def check_cert_on_revoke(serial_number, **kwargs):
    """Функция определяет отозванность сертификата по url или authKey crl и возвращает инмормационную строку"""

    def download_crl(d_url):
        print(d_url)
        crl_file_location = join(tmp_dir, 'get_by_url.crl')
        try:
            response = requests.get(d_url, timeout=(1, None))
            if response.status_code == 200:
                crl_data = response.content
                # записываем данные в файл
                with open(crl_file_location, mode='wb') as crl_out_f:
                    crl_out_f.write(crl_data)
            else:
                print(response.status_code)
                print('Невозможно загрузить файл по ссылке %s' % url)
                exit(1)
        except requests.exceptions.RequestException as e:
            print('Невозможно загрузить файл по ссылке %s' % url)
            print(e)
            exit(1)
        return crl_file_location

    def checking(crl_file_l):
        try:
            crl = Crl(crl_file_l, timezone=timezone)
            revoked_d = crl.get_revoked_certs_info(certificate_serial=serial_number)
            if revoked_d:
                print('''Сертификат "%s" отозван %s по причине "%s" ''' % (serial_number,
                                                                           revoked_d['revoke_date'],
                                                                           revoked_d['reason']))
            else:
                print('Сертификат "%s" не отзывался' % serial_number)

            crl_info = crl.compile_info_v5()
            this_update = crl_info.get_this_update_datetime()
            next_update = crl_info.get_next_update_datetime()

            if not this_update <= datetime.now() <= next_update:
                print('Срок действия Crl: с %s по %s (НЕ АКТУАЛЕН)' % (this_update, next_update))
            else:
                print('Срок действия Crl: с %s по %s (АКТУАЛЕН)' % (this_update, next_update))

        except Crypto_error:
            print('Ошибка обработки SSL crypto')
            exit(1)
        except ImportError:
            print('Превышен допустимый размер файла')
            exit(1)

    # ##########
    if 'subj_key_id' in kwargs.keys():
        subj_key_id = kwargs['subj_key_id'].replace(' ', '')
        crl_file_urls = cn.execute_query(
            get_crl_file_urls_by_subj_key_id_query % subj_key_id)
        for crl_file_url in crl_file_urls:
            crl_file_url = crl_file_url[0]
            crl_file_location = download_crl(crl_file_url)
            checking(crl_file_location)
            print('\n')

    elif 'url' in kwargs.keys():
        url = kwargs['url']
        crl_file_location = download_crl(url)
        checking(crl_file_location)

    elif 'hash' in kwargs.keys():
        c_hash = kwargs['hash']
        crl_file_location = return_value_with_len_check(cn.execute_query(get_crl_location_by_hash % c_hash),
                                                        'Hash')
        checking(crl_file_location)


def delete_old_data(server, days):
    print('Удаление данных старше %s дней для сервера %s' % (days, server))
    locations = cn.execute_query(get_file_locations_for_delete_query, days, server)
    if locations:
        for location in locations:
            try:
                remove(location[0])
            except:
                pass
            cn.execute_query(delete_old_bd_record_query, days, server)


def update_crl_info_by_auth_id(server, auth_key):
    auth_key = auth_key.replace(' ', '')
    urls = cn.execute_query(get_urls_by_subj_key_and_server % (value_former(auth_key), server))
    if urls:
        for url in urls:
            url = url[0]
            crl_updater(server, url)
        print('Данные по auth_key "%s" для сервера %s успешно обновлены' % (auth_key, server))
    else:
        print('Данные по auth_key "%s" для сервера %s не найдены. Обновить невозможно' % (auth_key, server))


if __name__ == '__main__':
    logger = logger_module.logger()
    try:
        # парсим аргументы командной строки
        my_parser = create_parser()
        namespace = my_parser.parse_args()

        if namespace.version:
            show_version()
            exit(0)

        if namespace.check_revoke_status:
            if not namespace.certificate_number:
                print('Не указан certificate_number')
                exit(1)

            if not (namespace.url or namespace.auth_key or namespace.hash):
                print('Требуется указать url, auth_key или hash')
                exit(1)

            elif namespace.url:
                check_cert_on_revoke(namespace.certificate_number, url=namespace.url)
                exit(0)

            elif namespace.auth_key:
                check_cert_on_revoke(namespace.certificate_number, subj_key_id=namespace.auth_key)
                exit(0)

            elif namespace.hash:
                check_cert_on_revoke(namespace.certificate_number, hash=namespace.hash)
                exit(0)

        if namespace.remove:
            if namespace.server:
                u_server_list.append(namespace.server)
            else:
                u_server_list = d_server_list

            if namespace.days:
                days = namespace.days
            else:
                days = d_days

            for server in u_server_list:
                delete_old_data(server, days)

            print('Данные удалены')
            exit(0)

        if namespace.update:
            if namespace.server:
                u_server_list.append(namespace.server)
            else:
                u_server_list = d_server_list

            for server in u_server_list:
                url_l = get_and_parse_crl_url_file(server)

                u_status = 0
                bar = progressbar.ProgressBar(maxval=len(url_l), widgets=[
                    'Обработка сервера %s' % server,
                    progressbar.Bar(left=' [', marker='#', right='] '),
                    progressbar.SimpleProgress(),
                ]).start()

                for url in url_l:
                    crl_updater(server, url)
                    u_status += 1
                    bar.update(u_status)
                bar.finish()

                print('Обработка завершена')
            exit(0)

        if namespace.fast_update_by_auth_key:
            if not namespace.auth_key:
                print('Не указан auth_key')
                exit(1)

            if namespace.server:
                u_server_list.append(namespace.server)
            else:
                u_server_list = d_server_list
            for server in u_server_list:
                update_crl_info_by_auth_id(server, namespace.auth_key)
            exit(0)

        else:
            show_version()
            print('For more information run use --help')
    # если при исполнении будут исключения - кратко выводим на терминал, остальное - в лог
    except Exception as e:
        logger.fatal('Fatal error! Exit', exc_info=True)
        print('Critical error: %s' % e)
        print('More information in log file')
        exit(1)

    exit(0)



