# -*- coding: utf-8 -*-
import os
import sys
import time
from datetime import datetime
import gevent
import random
from celery import Celery
from gevent.pool import Pool
from gevent.timeout import Timeout, with_timeout
from pyabs import PyABS, logto, DEBUG, WARNING, INFO, SUCCESS, SFTP_SUCCESS
# from pyabs import logger
logger = logto('with_gevent_log.txt', name='with_gevent', level=INFO)


class TimeOutException(Exception):
    pass

app = Celery('with_gevent', broker='amqp://guest@localhost//')
TaskPool = Pool(16)
TaskPool1 = Pool(2)

def sftp_task(task_info):
    import posixpath
    client = task_info.get('client')
    filename = task_info.get('filename')
    dst = task_info.get('dst')
    filepath = posixpath.join(dst, filename)
    ret, code = client.sftp(filename, filepath)
    return code

def exec_task(client):
    client.open_channel()   # must open channel befroe excute cmd
    client.exec_command('ip addr show eth1 && hostname')
    client.exec_command("cd /tmp && rm -rf *")
    client.exec_command("cd /tmp && mkdir test test1 test2 test3 test4")

def checker(r):
    for _ in r:
        if _ < 0:
            return False
    return True

@app.task
def test_multi_server(pyabs, filename, dst):
    result = []
    start = time.time()
    logger.info('test start: %s', start)
    # ============================================================

    def mapper(server):
        c = PyABS(server)
        code, msg = c.login(timeout=3)
        if code == SUCCESS:
            exec_task(c)
            return {'client': c, 'filename': filename, 'dst': dst}
        else:
            logger.error(msg)
    tasks = map(mapper, pyabs)

    try:
        with Timeout(600, TimeOutException) as timeout:
            for t in TaskPool.imap_unordered(sftp_task, tasks):
                print t, time.time()
                result.append(t)
    except TimeOutException, e:
        logger.error('*************time out*************')

    logger.info('test: close all client in tasks.')
    for task in tasks:
        task.get('client').close()
    # ============================================================

    end = time.time()
    logger.info('test end: %s, total: %s, filename: %s, dst: %s, result: %s', end, end - start, filename, dst, result)
    if checker(result):
        logger.info('send %s task all success.', filename)
    else:
        logger.error('send %s task not all success.', filename)

    return result


@app.task
def test_multi_file(server, files, dst):

    result = []
    start = time.time()

    c = PyABS(server)
    code, msg = c.login(timeout=3)
    if code == SUCCESS:
        exec_task(c)
        tasks = [{'client': c, 'filename': filename, 'dst': dst} for filename in files]
    else:
        tasks = []
        logger.error(msg)

    try:
        with Timeout(600, TimeOutException) as timeout:
            for t in TaskPool.imap_unordered(sftp_task, tasks):
                logger.info('%s, %s', t, time.time())
                result.append(t)
    except TimeOutException, e:
        logger.error('*************time out*************')

    if checker(result):
        logger.info('send %s task all success.', filename)
    else:
        logger.error('send %s task not all success.', filename)

    c.close()

    end = time.time()
    logger.info('test end: %s, total: %s, filename: %s, dst: %s, result: %s', end, end - start, files, dst, result)
    return result

def scp(task_info):
    import posixpath
    client = task_info.get('client')
    child = task_info.get('child')
    filename = task_info.get('filename')
    dst = task_info.get('dst')
    filepath = posixpath.join(dst, filename)
    code, output = client.scp(child, filepath, filepath)
    return code


@app.task
def test_multi_file1(server, files, dst, child):

    result = []
    start = time.time()

    c = PyABS(server)
    code, msg = c.login(timeout=3)
    if code == SUCCESS:
        exec_task(c)
        tasks = [{'client': c, 'filename': filename, 'dst': dst} for filename in files]
    else:
        tasks = []
        logger.error(msg)

    try:
        with Timeout(600, TimeOutException) as timeout:
            for t in TaskPool.imap_unordered(sftp_task, tasks):
                logger.info('%s, %s', t, time.time())
                result.append(t)
    except TimeOutException, e:
        logger.error('*************time out*************')

    for task in tasks:
        task.update({'child': child})

    # tasks = [
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'a.mp4'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'b.mp4'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'c.mp4'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'd.mp4'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'e.mp4'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'f.mp4'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'a.zip'},
    #     {'child': child, 'client': c, 'dst': '/tmp', 'filename': 'b.zip'},
    # ]

    # pyabs:713: scp exception: (1, 'Administratively prohibited')
    # Traceback (most recent call last):
    #   File "F:\apps\python\pyabs\pyabs.py", line 699, in scp
    #     chan = self.client.invoke_shell()
    #   File "D:\Python27\lib\site-packages\paramiko\client.py", line 428, in invoke_shell
    #     chan = self._transport.open_session()
    #   File "D:\Python27\lib\site-packages\paramiko\transport.py", line 702, in open_session
    #     timeout=timeout)
    #   File "D:\Python27\lib\site-packages\paramiko\transport.py", line 834, in open_channel
    #     raise e
    # ChannelException: (1, 'Administratively prohibited')

    # logger.warning(tasks)
    # send file to other servers
    if child:
        # c.scp(child, '/tmp/*.mp4', '/tmp/')
        try:
            with Timeout(600, TimeOutException) as timeout:
                for t in TaskPool1.imap_unordered(scp, tasks):
                    print t, time.time()
                    result.append(t)
        except TimeOutException, e:
            logger.error('*************time out*************')

    if checker(result):
        logger.info('send %s task all success.', files)
    else:
        logger.error('send %s task not all success.', files)

    c.close()
    end = time.time()
    logger.info('test end: %s, total: %s, filename: %s, dst: %s, result: %s', end, end - start, files, dst, result)
    return result

if __name__ == '__main__':
    proxy = {'host': '11.11.1.2', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p', 'key_path': 'id_rsa'}
    client1 = {'host': '11.11.1.3', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    client2 = {'host': '11.11.1.4', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    client3 = {'host': '11.11.1.5', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    client4 = {'host': '11.11.1.6', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    client5 = {'host': '11.11.1.7', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    pyabs = [proxy, client1, client2, client3, client4, client5]
    # test_multi_server.delay(pyabs[3:], 'a.zip', '/tmp')
    # test_multi_server.delay(pyabs[:], 'a.zip', '/tmp/test')
    # test_multi_server.delay(pyabs[:], 'a.zip', '/tmp/test1')
    # test_multi_server.delay(pyabs[:], 'a.zip', '/tmp/test2')
    # test_multi_server.delay(pyabs[:], 'a.zip', '/tmp/test3')
    # test_multi_server.delay(pyabs[:], 'a.zip', '/tmp/test4')
    # test.delay('data.zip', '~')
    test_multi_file1.delay(proxy, ['a.mp4', 'b.mp4', 'c.mp4', 'd.mp4', 'e.mp4', 'f.mp4', 'a.zip', 'b.zip'], '/tmp', client4)
    test_multi_file1.delay(client1, ['a.mp4', 'b.mp4', 'c.mp4', 'd.mp4', 'e.mp4', 'f.mp4', 'a.zip', 'b.zip'], '/tmp', client2)
    # test_multi_file.delay(client1, ['a.mp4', 'b.mp4', 'c.mp4', 'd.mp4', 'e.mp4', 'f.mp4'], '/tmp')
    # test_multi_file.delay(client2, ['a.mp4', 'b.mp4', 'c.mp4', 'd.mp4', 'e.mp4', 'f.mp4'], '/tmp')
    return 0
