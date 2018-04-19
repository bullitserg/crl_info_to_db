import re
import requests
from os import remove
from hashlib import md5
from ets.ets_certificate_lib import Crl
from ets.ets_certmanager_logs_parser import get_crl_point_file
from datetime import datetime, timedelta
from OpenSSL.crypto import Error as Crypto_error
from queries import *
from ets.ets_mysql_lib import NULL, value_former
from os.path import normpath, join
from ets.ets_mysql_lib import MysqlConnection as mc
from config import *

tmp_dir = normpath(tmp_dir)

cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
cn.connect()


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


def crl_updater(server, url, template):

    info_data = {'server': value_former(server),
                 'url': value_former(url),
                 'template': template}

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


def delete_old_data(server, minutes):
    print('Удаление данных старее %s минут для сервера %s' % (minutes, server))
    locations = cn.execute_query(get_file_locations_for_delete_query, minutes, server)
    if locations:
        for location in locations:
            try:
                remove(location[0])
            except:
                pass
            cn.execute_query(delete_old_bd_record_query, minutes, server)


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


