# test.py
# -*- coding: utf-8 -*-
import os
from pyabs import PyABS, SUCCESS, logger, SFTP_SUCCESS
import datetime

def test():
    '''
    connection map
    (localhost)pabs->proxy--|-->client1->client3
                   |        |-->client2->client4
                   |-->client5
    '''
    # auth with password
    proxy = {'host': '11.11.1.2', 'port': 22, 'username': 'vagrant',
             'password': 'vagrant', 'auth_type': 'p'}
    client1 = {'host': '11.11.1.3', 'port': 22, 'username': 'vagrant',
               'password': 'vagrant', 'auth_type': 'p'}
    # auth with rsa
    client2 = {'host': '11.11.1.4', 'port': 22, 'username': 'vagrant',
               'password': 'vagrant', 'auth_type': 'r','key_path': '~/.ssh/id_dsa'}
    client3 = {'host': '11.11.1.5', 'port': 22, 'username': 'vagrant',
               'password': 'vagrant', 'auth_type': 'r','key_path': '~/.ssh/id_rsa'}
    client4 = {'host': '11.11.1.6', 'port': 22, 'username': 'vagrant',
               'password': 'vagrant', 'auth_type': 'p'}
    client5 = {'host': '11.11.1.7', 'port': 22, 'username': 'vagrant',
               'password': 'vagrant', 'auth_type': 'p'}
    # connect proxy
    pabs = PyABS(proxy)
    # connect client5
    pclient5 = PyABS(client5)

    # ===========================================pabs->proxy==================================
    logger.warning('++++++++++++++++pabs->proxy++++++++++++++++')
    code, msg = pabs.login(timeout=3)
    if code == SUCCESS:
        ret = pabs.rm('/tmp/test')
        if ret:
            logger.debug('rm success.')
        pabs.mkdir('/tmp/test/')
        filename = os.path.basename(__file__)
        ret, code = pabs.sftp(filename, '/tmp/test/%s' % filename)
        if code == SFTP_SUCCESS:
            logger.debug('sftp %s bytes.' % ret.st_size)
            pabs.open_channel()  # must open channel befroe excute cmd
            pabs.exec_command('cd /tmp')
            pabs.exec_command('tar -zcvf test.tar.gz /tmp/*', timeout=60)
            pabs.exec_command('ls /tmp -l')
            # ===============================proxy->client1[t1]=================================
            logger.warning('++++++++++++++++proxy->client1[t1]++++++++++++++++')
            pabs.scp(client1, src='/tmp/*.tar.gz', dst='/tmp/')
            pabs.scp(client1, src='/tmp/a.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/b.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/c.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/d.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/e.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/f.mp4', dst='/tmp/')
            t1, code, output = pabs.ssh(client1)
            assert (code == SUCCESS)
            t1.exec_command('ip addr show eth1 && hostname')
            t1.exec_command('ls /tmp/ -l')
            # ====================================client1->client3[t1]==========================
            logger.warning('++++++++++++++++client1->client3[t1]++++++++++++++++')
            code, output = t1.scp(client3, src='/tmp/test.tar.gz', dst='/tmp/')
            assert (code == SUCCESS)
            code, output = t1.ssh(client3)
            assert (code == SUCCESS)
            t1.exec_command('ip addr show eth1 && hostname')
            t1.exec_command('ls /tmp/ -l')
            # ================================proxy->client2[t2]===============================
            logger.warning('++++++++++++++++proxy->client2[t2]++++++++++++++++')
            pabs.scp(client2, src='/tmp/*.tar.gz', dst='/tmp/')
            t2, code, output = pabs.ssh(client2)
            assert (code == SUCCESS)
            t2.exec_command('ip addr show eth1 && hostname')
            t2.exec_command('ls /tmp/ -l')

            # ==============================client2->client4[t2]===============================
            logger.warning('++++++++++++++++client2->client4[t1]++++++++++++++++')
            code, output = t2.scp(client4, src='/tmp/test.tar.gz', dst='/tmp/')
            assert (code == SUCCESS)
            code, output = t2.ssh(client4)
            assert (code == SUCCESS)
            t2.exec_command('ls /tmp/ -l')
            # =================================================================================
            pabs.close()
            # =================================================================================
            logger.warning('++++++++++++++++client5++++++++++++++++')
    code, msg = pclient5.login(timeout=3)
    if code == SUCCESS:
        pclient5.mkdir('/tmp/test')
    else:
        logger.debug(msg)
    pclient5.close()

if __name__ == '__main__':
    test()
    print 'xxxxx'
    return 0
