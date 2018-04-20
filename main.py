import argparse
import logger_module
import progressbar
from functions import *


PROGNAME = 'Crl data downloader'
DESCRIPTION = '''Скрипт для импортирования данных из списка url и сохранения данных по ним в базу данных'''
VERSION = '1.0'
AUTHOR = 'Belim S.'
RELEASE_DATE = '2018-04-05'

u_server_list = []
template = 0


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
                        --server - обновить для указанного сервера (необязательный)
                        --template - установить как шаблон, удобно для последующей
                        работы с --fast_update_by_auth_key''')

    parser.add_argument('-f', '--fast_update_by_auth_key', action='store_true',
                        help='''Быстрое обновление данных по auth_key.
                        Аргументы:
                        --auth_key - идентификатор (обязательный);
                        --server - обновить для указанного сервера (необязательный)''')

    parser.add_argument('-r', '--remove', action='store_true',
                        help='''Удалить устаревшие записи.
                        Аргументы:
                        --server - удалить для указанного сервера (необязательный);
                        --minutes - старее, чем minutes минут (по умолчанию 0, необязательный)''')

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

    parser.add_argument('-t', '--template', action='store_true',
                        help="Записать как шаблон")

    parser.add_argument('-k', '--auth_key', type=str,
                        help="Установить auth_key")

    parser.add_argument('-l', '--url', type=str,
                        help="Установить url")

    parser.add_argument('-a', '--hash', type=str,
                        help="Установить md5-хеш")

    parser.add_argument('-n', '--certificate_number', type=str,
                        help="Установить номер сертификата")

    parser.add_argument('-m', '--minutes', type=int,
                        help="Установить количество минут")

    return parser


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

            if namespace.minutes:
                minutes = namespace.minutes
            else:
                minutes = d_minutes

            for server in u_server_list:
                delete_old_data(server, minutes)

            info = 'Сведения за %s минут удалены' % minutes
            print(info)
            logger.info(info)

            exit(0)

        if namespace.update:

            if namespace.template:
                template = 1

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
                    crl_updater(server, url, template)
                    u_status += 1
                    bar.update(u_status)
                bar.finish()

            info = 'Данные обновлены'
            print(info)
            logger.info(info)

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

            info = 'Выполнено быстрое обновление по auth_key "%s"' % namespace.auth_key
            logger.info(info)

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



