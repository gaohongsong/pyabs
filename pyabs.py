# coding=utf8
import os
import re
import stat
import sys
import socket
import logging
import posixpath
import datetime
import time
# import traceback
import paramiko
# import gevent

from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL

# pyabs日志
def logto(filename, name=__name__, level=DEBUG):
    # filename = '%s_%s.text' % (filename, datetime.datetime.now().strftime('%Y_%m_%d'))
    # f = os.path.join(os.path.realpath('.'), filename)
    logger = logging.getLogger(name)
    # logger = logging.getLogger('pyabs')
    # if len(logger.handlers) > 0:
    #     return
    logger.setLevel(level)
    formatter = logging.Formatter(
        '%(levelname)-.3s [%(asctime)s.%(msecs)03d] %(threadName)-10s %(name)s:%(lineno)03d: %(message)s',
        '%Y%m%d-%H:%M:%S')
    file_handler = logging.FileHandler(filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if level == DEBUG:
        stream_handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(stream_handler)
    return logger

# paramiko日志
paramiko.util.log_to_file('paramiko.log')
# pyabs日志
logger = logto('pyabs.log', level=INFO)

# =================================================================================================================
# configs
REMOTE_KEY_PATH = ''
LOCAL_KEY_PATH = ''
# =================================================================================================================
# PyABS status code
SUCCESS = 1
SEND_KEY_SUCCESS = 100
SFTP_SUCCESS = 200

AUTH_TYPE_ERR = -4001
TIMEOUT_ERR = -4002
SSH_LOGIN_EXP = -4003
WRONG_PASSWD = -4004
WRONG_KEY = -4005
LOGIN_EXCP = -4006
SSH_SESSION_EXP = -4007
UNEXPECT_RETURN = -4008
CON_REFUSED = -4009
WRONG_FILE_MODE = -4010
COMMON_ERROR = -4011
SEND_KEY_EXP = -4012
SSH_EXP = -4013
SCP_EXP = -4014
SFTP_EXP = -4015
# =================================================================================================================
class SshInterpreter(object):
    '''
    决策机
    '''
    displaypassinfo = "assword:"
    displaypassinfo1 = "Password:"
    fingerprintinfo = "fingerprint:"
    lostconnectinfo = 'lostconnection'
    timeoutinfo = 'Noroutetohost'
    timeoutinfo1 = 'Connectiontimedout'
    timeoutinfo2 = 'Connectiontimeout'
    refusedinfo = 'Connectionrefused'
    yes_or_no = "yes/no"
    yes_or_no2 = "'yes'or'no':"
    permisstion_deny = 'Permissiondenied'
    publickey_deny = 'Permissiondenied(publickey'
    key_login_required = 'publickey,gssapi-keyex,gssapi-with-mic'
    add_to_known_hosts = 'tothelistofknownhosts'
    too_open = 'tooopen'
    ignore_key = 'ignorekey'
    invalid_key = 'passphraseforkey'
    no_such_file = 'Nosuchfileordirectory'
    unique_prompt = "PYABSPYABSPYABS"
    trans = {
        'p': 'password',
        'r': 'rsa public key',
        'd': 'dsa public key',
    }

    def __init__(self, chan):
        self.UNIQUE_PROMPT = "\[PYABS\][\$\#] "
        self.PROMPT = self.UNIQUE_PROMPT
        self.PROMPT_SET_SH = "export PS1='[PYABS]\$ '"  # 'export PS1="[\u@\h_BKproxy \W]\$"' for sh
        self.PROMPT_SET_CSH = "set prompt='[PYABS]\$ '"  # for csh
        self.RECV_MAX_BYTE = 4096  # recv max char
        self.RECV_TIMEOUT = 5  # recv time out
        self.PROMPT_TIMEOUT = 30  # recv prompt time out
        self.CON_TIMEOUT = 10  # ssh connection time out
        self.SLEEP_INTERVAL = 0.005  # sleep interval before recv next
        self.MaxCheck = 30  # wait for recv ready
        self.WAIT_LOGIN = 1  # wait after password inputed
        # TODO chan=None
        self.chan = chan

    def clear(self, s):
        _s = re.sub(r'\\u001b\[\D{1}|\[\d{1,2}\D?|\\u001b\[\d{1,2}\D?~?|\r|\n|\s{1,}', '', s)
        _s = re.sub(r'\$.{0,1}\[\D{1}', '$', _s)
        return _s

    def clear_yes_or_no(self, s):
        return s.replace(self.yes_or_no, '').replace(self.yes_or_no2, '')

    def is_wait_passwd_input(self, buff):
        buff = self.clear(buff)
        return buff.endswith(self.displaypassinfo) or buff.endswith(self.displaypassinfo1)

    def is_too_open(self, buff):
        buff = self.clear(buff)
        return buff.find(self.too_open) != -1 or buff.find(self.ignore_key) != -1

    def is_permission_denied(self, buff):
        buff = self.clear(buff)
        return buff.find(self.permisstion_deny) != -1

    def is_publickey_denied(self, buff):
        buff = self.clear(buff)
        return buff.find(self.publickey_deny) != -1

    def is_invalid_key(self, buff):
        buff = self.clear(buff)
        return buff.find(self.invalid_key) != -1

    def is_timeout(self, buff):
        buff = self.clear(buff)
        return buff.find(self.lostconnectinfo) != -1 or \
               buff.find(self.timeoutinfo) != -1 or \
               buff.find(self.timeoutinfo1) != -1 or \
               buff.find(self.timeoutinfo2) != -1

    def is_key_login_required(self, buff):
        buff = self.clear(buff)
        return buff.find(self.key_login_required) != -1

    def is_refused(self, buff):
        buff = self.clear(buff)
        return buff.find(self.refusedinfo) != -1

    def is_fingerprint(self, buff):
        buff = self.clear(buff)
        return buff.find(self.fingerprintinfo) != -1

    def is_wait_known_hosts_add(self, buff):
        buff = self.clear(buff)
        return buff.find(self.add_to_known_hosts) != -1

    def is_wait_yes_input(self, buff):
        buff = self.clear(buff)
        return buff.find(self.yes_or_no) != -1 or buff.find(self.yes_or_no2) != -1

    def is_console_ready(self, buff):
        buff = self.clear(buff)
        return buff.endswith('#') or buff.endswith('$') or buff.endswith('>')

    def is_lastlogin(self, buff):
        buff = self.clear(buff)
        return buff.find('Lastlogin') != -1

    def is_empty(self, buff):
        buff = self.clear(buff)
        return not buff

    def is_common_error(self, buff):
        buff = self.clear(buff)
        return buff.find(self.no_such_file) != -1

    def is_transport_file(self, buff):
        buff = self.clear(buff)
        return buff.find("ETA") != -1 or buff.find("scp:warning:") != -1

    def is_transported_over(self, buff):
        buff = self.clear(buff)
        return buff.find("100%") != -1

    def replace_prompt(self, buff, prompt):
        return buff.replace(prompt, self.unique_prompt)

    def is_prompt_seted(self, buff, prompt):
        return re.compile(prompt).search(buff) != None

    def get_buff_after_prompt(self, buff):
        return buff.split(self.unique_prompt)[-1]

    def wait(self, seconds):
        time.sleep(seconds)

    def recvall(self, chan):
        buff = ''
        chan.settimeout(1)
        while True:
            try:
                res = chan.recv(self.RECV_MAX_BYTE)
                buff += res
                if res == '':
                    break
            except socket.timeout:
                break
        return buff

    def wait_for_recv_ready(self, chan):
        check_cnt = 0
        while not chan.recv_ready():
            check_cnt += 1
            if check_cnt > self.MaxCheck:
                break
            self.wait(self.SLEEP_INTERVAL)

    def wait_for_cmd_over(self, chan, timeout=5):
        buff, res = '', ''
        old_timeout = chan.gettimeout()
        chan.settimeout(timeout)
        logger.debug('wait_for_cmd_over: old_timeout [%ss] -> timeout [%ss]', old_timeout, chan.gettimeout())
        while not self.is_console_ready(res):
            try:
                res = chan.recv(self.RECV_MAX_BYTE)
                buff += res
                self.wait(self.SLEEP_INTERVAL)
            except socket.timeout:
                logger.exception('wait_for_cmd timeout.')
                raise ExecuteException('wait_for_cmd timeout.')
        chan.settimeout(old_timeout)
        logger.debug('wait_for_cmd_over: timeout [%ss] -> old_timeout [%ss]', timeout, chan.gettimeout())
        return buff

    def get_channel(self):
        return self.chan

    def set_channel(self, chan, blocking=0, timeout=-1):
        # set socket read time out
        chan.setblocking(blocking=blocking)
        # settimeout(0) -> setblocking(0)
        # settimeout(None) -> setblocking(1)
        timeout = self.RECV_TIMEOUT if timeout < 0 else timeout
        chan.settimeout(timeout=timeout)

    def close_channel(self):
        try:
            logger.info('close channel-%s', self.chan.get_id())
            self.safe_close(self.chan)
            self.chan = None
        except:
            pass

    def safe_close(self, obj):
        try:
            obj.close()
        except:
            pass

    def execute(self, chan, cmd, timeout):
        buff = ''
        try:
            logger.debug('start execute: [ %s ]', cmd)
            cmd = cmd + '\n' if not cmd.endswith('\n') else cmd
            chan.sendall(cmd)
            self.wait_for_recv_ready(chan)
            buff = self.wait_for_cmd_over(chan, timeout)
            logger.info('ended execute: %s%s>\n %s \n%s<\n', cmd, '-'*100, buff, '-'*100)
        except ExecuteException, e:
            logger.exception('execute ExecuteException: %s', e)
        except Exception, e:
            logger.exception('execute Exception: %s', e)
        return buff

    def exec_command(self, cmd, timeout=5):
        logger.info('exec_command: [%s], wait for %ss', cmd, timeout)
        return self.execute(self.chan, cmd, timeout)

    def get_prompt(self, chan):
        # send enter key and get the prompt
        prompt = '######GET_PROMPT_ERR######'
        logger.debug('send enter.')
        chan.sendall('\n')
        while True:
            try:
                buff = chan.recv(self.RECV_MAX_BYTE)
                logger.debug('get_prompt: buff = <!--%s-->', buff)
                if self.is_console_ready(buff):
                    prompt = re.compile("\r\n|\n").split(buff)[-1]
                    logger.debug('get_prompt: recv prompt success. [%s]', prompt)
                    break
                logger.debug('get_prompt: sleep %ss for next recv.', self.SLEEP_INTERVAL)
                self.wait(self.SLEEP_INTERVAL)
            except socket.timeout:
                logger.exception('get_prompt timeout.')
                break
        return prompt

    def set_prompt(self, chan):
        # set a new prompt in order to make interact easy
        chan.sendall(self.PROMPT_SET_SH + '\n')
        while True:
            try:
                buff = chan.recv(self.RECV_MAX_BYTE)
                logger.debug('set_prompt: buff = <!--%s-->', buff)
                if self.is_prompt_seted(buff, self.PROMPT):
                    is_seted = True
                    logger.debug('set_prompt success.')
                    break
                self.wait(self.SLEEP_INTERVAL)
                logger.debug('set_prompt: sleep %ss for next recv.', self.SLEEP_INTERVAL)
            except socket.timeout:
                logger.exception('set_prompt timeout.')
                is_seted = False
                break
        return is_seted

    def get_and_set_prompt(self, chan):
        old_prompt, new_prompt = '######GET_PROMPT_ERR######', ''
        old_timeout = chan.gettimeout()
        chan.settimeout(self.PROMPT_TIMEOUT)
        timeout = chan.gettimeout()
        logger.debug('get_and_set_prompt: old_timeout [%ss] -> timeout [%ss]', old_timeout, timeout)

        try:
            old_prompt = self.get_prompt(chan)
            is_seted = self.set_prompt(chan)
            if is_seted:
                new_prompt = self.get_prompt(chan)
                logger.info('get_and_set_prompt success: [ %s --> %s ]', old_prompt, new_prompt)
            else:
                new_prompt = old_prompt
                logger.exception('set prompt failure: [ %s --> %s ]', old_prompt, new_prompt)
        except Exception, e:
            logger.exception('get_and_set_prompt exception: %s', e)
            new_prompt = old_prompt
            is_seted = False

        chan.settimeout(old_timeout)
        logger.debug('get_and_set_prompt: timeout [%ss] -> old_timeout [%ss]', timeout, chan.gettimeout())

        return is_seted, old_prompt, new_prompt

    def create_cmd(self, host, port, username, src=None, dst=None, s_type='ssh', key_path=None, timeout=10):
        '''
        根据认证类型及认证信息，生成ssh登录指令
        '''

        # auth through password
        if key_path:
            if s_type == 'ssh':
                # ssh task session
                cmd = 'ssh  -i {key_path} -p {port} -o ConnectTimeout={timeout} {username}@{hostname}\n'.format(
                    timeout=timeout,
                    port=port,
                    username=username,
                    hostname=host,
                    key_path=key_path
                )
            else:
                # scp task session
                cmd = 'scp -i {key_path} -r -o ConnectTimeout={timeout} -P {port} {src} {username}@{hostname}:{dst}\n'.format(
                    timeout=timeout,
                    port=port,
                    src=src,
                    dst=dst,
                    username=username,
                    hostname=host,
                    key_path=key_path
                )

        else:
            # auth through key
            if s_type == 'ssh':
                cmd = 'ssh -p {port} -o ConnectTimeout={timeout} {username}@{hostname}\n'.format(
                    timeout=timeout,
                    port=port,
                    username=username,
                    hostname=host
                )
            else:
                cmd = 'scp -r -o ConnectTimeout={timeout} -P {port} {src} {username}@{hostname}:{dst}\n'.format(
                    timeout=timeout,
                    port=port,
                    src=src,
                    dst=dst,
                    username=username,
                    hostname=host,
                    key_path=key_path
                )
        logger.debug('create_cmd: %s', cmd)
        return cmd

    def clear_login_tip(self, chan):
        buff = ''
        while True:
            try:
                res = chan.recv(self.RECV_MAX_BYTE)
                buff += res
                if self.is_console_ready(buff):
                    logger.debug('clear_login_tip exit recv console ready')
                    break
                elif self.is_lastlogin(buff):
                    logger.debug('clear_login_tip exit recv login info')
                    break
                self.wait(self.SLEEP_INTERVAL)
            except socket.timeout:
                logger.exception('clear_login_tip exit timeout.')
                break
        return buff

    def open_session(self, chan, cmd, password=None, auth_type='p'):
        output = ''
        logger.info('start open_session, auth type(%s)', self.trans.get(auth_type))
        # eat the ssh login message
        # output += self.clear_login_tip(chan)
        # get and set the current shell prompt TODO
        is_seted, old_prompt, prompt = self.get_and_set_prompt(chan)
        # execute ssh instruction
        chan.sendall(cmd)
        # wait for at least 1s for output
        # self.wait(self.WAIT_LOGIN)
        buff = ''
        if auth_type == 'p':
            while True:
                self.wait(self.SLEEP_INTERVAL)
                try:
                    res = chan.recv(self.RECV_MAX_BYTE)
                    output += res
                    # 替换主机shell提示符
                    buff += self.clear(res)
                    buff = self.replace_prompt(buff, prompt)
                except socket.timeout:
                    msg = 'wait_for_password timeout after wait for %s seconds: socket timeout' % self.RECV_TIMEOUT
                    logger.exception(msg)
                    return UNEXPECT_RETURN, output
                except Exception, e:
                    msg = 'session failed, exception: %s' % e
                    logger.exception(msg)
                    return SSH_SESSION_EXP, output
                if self.is_wait_passwd_input(buff):
                    break
                elif self.is_timeout(buff):
                    return TIMEOUT_ERR, output
                elif self.is_refused(buff):
                    return CON_REFUSED, output
                elif self.is_publickey_denied(buff):
                    return AUTH_TYPE_ERR, output
                elif self.is_wait_yes_input(buff):
                    chan.sendall('yes\n')
                    buff = self.clear_yes_or_no(buff)
                    self.wait(self.SLEEP_INTERVAL)
                elif self.is_console_ready(buff):
                    return SUCCESS, output
            # vagrant@11.11.1.3's password:
            chan.sendall(password + '\n')
        else:
            # 密钥认证
            self.wait(self.WAIT_LOGIN)
        buff = ''
        # if we auth success, got ouput ends with '# ' or '$ ':
        while True:
            self.wait(self.SLEEP_INTERVAL)
            try:
                res = chan.recv(self.RECV_MAX_BYTE)
                output += res
                # 替换主机shell提示符
                buff += self.clear(res)
                buff = self.replace_prompt(buff, prompt)
            except socket.timeout:
                msg = 'wait_for_console_ready timeout after wait for %s seconds.' % self.RECV_TIMEOUT
                logger.exception(msg)
                return UNEXPECT_RETURN, output
            except Exception, e:
                # lost connection
                msg = 'session failed, exception: %s' % e
                logger.exception(msg)
                return SSH_SESSION_EXP, output
            if self.is_wait_passwd_input(buff):
                if self.is_too_open(buff):
                    return WRONG_FILE_MODE, output
                else:
                    return WRONG_PASSWD, output
            # the only right exit point
            elif self.is_console_ready(buff):
                return SUCCESS, output
            elif self.is_wait_yes_input(buff):
                chan.sendall('yes\n')
                buff = self.clear_yes_or_no(buff)
                self.wait(self.SLEEP_INTERVAL)
            elif self.is_timeout(buff):
                return TIMEOUT_ERR, output
            elif self.is_publickey_denied(buff) or self.is_invalid_key(buff):
                return WRONG_KEY, output
            elif self.is_common_error(buff):
                return COMMON_ERROR, output

# =================================================================================================================
class PyABSException(Exception):
    pass


class ExecuteException(PyABSException):
    pass


# =================================================================================================================
class PyTerminal(SshInterpreter):
    def __init__(self, chan):
        # super(PyTerminal, self).__init__()  # multi inherit
        SshInterpreter.__init__(self, chan)
        self.depth = 1

    def close(self):
        buff = ''
        logger.info('close PyTerminal terminals and channel')
        try:
            for i in range(self.depth):
                res = self.exec_command('exit')
                buff += res
            logger.debug('close PyTerminal channel')
            self.close_channel()
        except Exception, e:
            buff += 'close exception: %s' % e
            logger.exception(buff)
        return buff

    def ssh(self, server, timeout=10):
        host = server.get('host')
        port = server.get('port')
        username = server.get('username')
        password = server.get('password')
        key_path = server.get('key_path')
        auth_type = server.get('auth_type')
        try:
            # generate ssh instructions by auth type, key or password
            cmd = self.create_cmd(host, port, username, 'ssh', key_path=key_path, timeout=timeout)
            code, output = self.open_session(self.chan, cmd, password, auth_type)
            if code == SUCCESS:
                self.depth += 1

            if code != SUCCESS:
                logger.error('ssh failed, code: [%s]', code)
            else:
                logger.info('ssh %s@%s using(%s) success.', username, host, self.trans.get(auth_type))
            logger.debug('ssh: %s %s>\n %s \n%s<', cmd, '-'*100, output,  '-'*100)

        except Exception as e:
            code, output = SSH_EXP, 'ssh exception'
            logger.exception('ssh exception: %s' % e)
        return code, output

    def scp(self, server, src, dst, timeout=10):
        host = server.get('host')
        port = server.get('port')
        username = server.get('username')
        password = server.get('password')
        key_path = server.get('key_path')
        auth_type = server.get('auth_type')
        try:
            # generate scp instructions by auth type, key or password
            cmd = self.create_cmd(host, port, username, src, dst, 'scp', key_path=key_path, timeout=timeout)
            start_clock = time.clock()
            code, output = self.open_session(self.chan, cmd, password, auth_type)
            end_clock = time.clock()
            elapsed = end_clock - start_clock
            if code != SUCCESS:
                logger.error('scp failed, code: %s', code)
            else:
                logger.info('scp %s to %s success, elapsed %ss', src, dst, elapsed)
            logger.debug('scp: %s %s>\n %s \n%s<', cmd, '-'*100, output,  '-'*100)

        except Exception as e:
            code, output = SCP_EXP, 'scp exception'
            logger.exception('scp exception: %s', e)
        return code, output

# =================================================================================================================
class PyABS(SshInterpreter):

    def __init__(self, server):
        # super(PyABS, self).__init__()  # multi inherit
        SshInterpreter.__init__(self, None)
        self.server = server  # save server info
        self.client = None  # save ssh client to server
        self.terminal = []

    # ***************************************************************************************
    def open_channel(self):
        if not self.chan:
            # open a shell, and get a channel to the shell
            self.chan = self.client.invoke_shell()
            self.set_channel(self.chan)
            logger.info('open channel-%s', self.chan.get_id())

    def close(self):
        # close all terminal ssh from proxy, then close proxy channel
        buff = ''
        logger.info('close PyABS opened terminals and channels')
        try:
            for t in self.terminal:
                res = t.close()
                buff += res
            logger.debug('close PyABS opened channels')
            self.close_channel()
        except Exception, e:
            buff += 'close pyabs exception: %s' % e
            logger.exception(buff)
        return buff
    # ***************************************************************************************

    def login(self, timeout=10):
        host = self.server.get('host')
        port = self.server.get('port')
        username = self.server.get('username')
        password = self.server.get('password')
        key_path = self.server.get('key_path')
        auth_type = self.server.get('auth_type')
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if auth_type == 'p':
                self.client.connect(host, port, username, password, timeout=timeout)
                msg = '%s@%s:%s login(password) success.' % (username, host, port)
                code = SUCCESS
            elif auth_type == 'r':
                try:
                    pkey = paramiko.RSAKey.from_private_key_file(key_path)
                except paramiko.PasswordRequiredException:
                    pkey = paramiko.RSAKey.from_private_key_file(key_path, password)
                self.client.connect(hostname=host, username=username, port=port, pkey=pkey, timeout=timeout)
                msg = '%s@%s:%s login(rsa) success.' % (username, host, port)
                code = SUCCESS
            elif auth_type == 'd':
                try:
                    pkey = paramiko.DSSKey.from_private_key_file(key_path)
                except paramiko.PasswordRequiredException:
                    pkey = paramiko.DSSKey.from_private_key_file(key_path, password)
                self.client.connect(hostname=host, username=username, port=port, pkey=pkey, timeout=timeout)
                msg = '%s@%s:%s login(dsa) success.' % (username, host, port)
                code = SUCCESS
            else:
                msg = 'SSH authentication method not supported. %s:(%s)' % (host, auth_type)
                code = AUTH_TYPE_ERR  # 不支持的认证方式
        except paramiko.BadHostKeyException, e:
            msg = 'SSH authentication key could not be verified.- %s@%s:%s - exception: %s' % (username, host, port, e)
            code = WRONG_KEY  # 密码错或者用户错
        except paramiko.AuthenticationException, e:
            msg = 'SSH authentication failed.- %s@%s:%s - exception: %s' % (username, host, port, e)
            code = WRONG_PASSWD  # 密码错或者用户错
        except paramiko.SSHException, e:
            msg = 'SSH connect failed.- %s@%s:%s - exception: %s' % (username, host, port, e)
            code = SSH_LOGIN_EXP  # 登录失败，原因可能有not a valid RSA private key file， 密钥文件不存在
        except socket.error:
            msg = 'TCP connect failed, timeout(%ss passed). - %s@%s:%s' % (timeout, username, host, port)
            code = TIMEOUT_ERR  # 超时
        except Exception, e:
            msg = 'login exception - %s@%s:%s: %s' % (username, host, port, e)
            code = LOGIN_EXCP  # 异常
        # log it
        if code == SUCCESS:
            logger.info(msg)
        else:
            logger.exception(msg)
        return code, msg
    # ***************************************************************************************

    def ssh(self, server, timeout=10):
        host = server.get('host')
        port = server.get('port')
        username = server.get('username')
        password = server.get('password')
        key_path = server.get('key_path')
        auth_type = server.get('auth_type')
        chan = None
        try:
            chan = self.client.invoke_shell()
            self.set_channel(chan)
            self.clear_login_tip(chan)
            # generate ssh instructions by auth type, key or password
            cmd = self.create_cmd(host, port, username, 'ssh', key_path=key_path, timeout=timeout)
            code, output = self.open_session(chan, cmd, password, auth_type)

            if code != SUCCESS:
                logger.error('ssh failed, code: [%s]', code)
            else:
                logger.info('ssh %s@%s using(%s) success.', username, host, self.trans.get(auth_type))
            logger.debug('ssh: %s %s>\n %s \n%s<', cmd, '-'*100, output,  '-'*100)

            terminal = PyTerminal(chan)
            self.terminal.append(terminal)
        except Exception as e:
            terminal, code, output = None, SSH_EXP, 'ssh exception'
            logger.exception('ssh exception: %s', e)
        return terminal, code, output

    def scp(self, server, src, dst, timeout=10):
        host = server.get('host')
        port = server.get('port')
        username = server.get('username')
        password = server.get('password')
        key_path = server.get('key_path')
        auth_type = server.get('auth_type')
        chan = None
        try:
            # create a new channel for new terminal
            chan = self.client.invoke_shell()
            self.set_channel(chan)
            self.clear_login_tip(chan)
            # generate scp instructions by auth type, key or password
            cmd = self.create_cmd(host, port, username, src, dst, 'scp', key_path=key_path, timeout=timeout)
            start_clock = time.clock()
            code, output = self.open_session(chan, cmd, password, auth_type)
            end_clock = time.clock()
            elapsed = end_clock - start_clock
            if code != SUCCESS:
                logger.error('scp failed, code: %s', code)
            else:
                logger.info('scp %s to %s success, elapsed %ss', src, dst, elapsed)
            logger.debug('scp: %s %s>\n %s \n%s<', cmd, '-'*100, output,  '-'*100)

        except Exception as e:
            code, output = SCP_EXP, 'scp exception'
            logger.exception('scp exception: %s', e)
        finally:
            logger.debug('scp: safe close channel for scp')
            self.safe_close(chan)
        return code, output
    # ***************************************************************************************

    def open_sftp(self):
        # sftp = paramiko.SFTPClient.from_transport(client.get_transport())
        # Open an SFTP session on the SSH server.
        sftp = self.client.open_sftp()
        logger.info('open_sftp: open sftp session success.')
        return sftp

    def sftp(self, src, dst):
        # sftp = paramiko.SFTPClient.from_transport(client.get_transport())
        sftp = self.open_sftp()
        try:
            s_stat = os.stat(src)
            start_time = datetime.datetime.now()
            start_clock = time.clock()
            logger.debug('start sftp %s to %s, size: %s bytes [%s]', src, dst, s_stat.st_size, start_time)
            ret = sftp.put(src, dst)
            end_time = datetime.datetime.now()
            end_clock = time.clock()
            elapsed = end_clock - start_clock
            logger.info('sftp %s to %s success, size: %s bytes, elapsed: %ss [%s]', src, dst, ret.st_size, elapsed, end_time)
            code = SFTP_SUCCESS
        except Exception, e:
            logger.exception('sftp %s failed, exception: %s', src, e)
            ret, code = None, SFTP_EXP
        finally:
            # safe close sftp session
            logger.info('sftp: safe close sftp session')
            self.safe_close(sftp)
        return ret, code
    # ***************************************************************************************

    def send_key(self, key):
        sftp = self.open_sftp()
        try:
            self.mkdir(REMOTE_KEY_PATH)
            src = os.path.join(LOCAL_KEY_PATH, key)
            dst = posixpath.join(REMOTE_KEY_PATH, key)
            logger.debug('send_key from %s to %s', src, dst)
            ret = sftp.put(src, dst)
            logger.debug("send_key: chmod %s's mode to 0400", dst)
            sftp.chmod(dst, 0400)
            code = SEND_KEY_SUCCESS
        except Exception, e:
            logger.exception('send_key exception: %s', e)
            ret, code = None, SEND_KEY_EXP
        finally:
            # safe close sftp session
            logger.debug('send_key: safe close sftp')
            self.safe_close(sftp)
        return ret, code

    def mkdir(self, directory):
        def _m(sftp, directory):
            # absolute directory
            if directory == '/':
                sftp.chdir('/')
                return
            # relative directory
            if directory == '':
                return
            # make sub directory
            try:
                sftp.chdir(directory)
            except IOError:
                d, name = os.path.split(directory.rstrip('/'))
                _m(sftp, d)
                logger.debug('mkdir %s', name)
                sftp.mkdir(name)
                sftp.chdir(name)
                return True

        sftp = self.open_sftp()
        try:
            _m(sftp, directory)
            ret = True
        except Exception:
            ret = False
        finally:
            logger.debug('mkdir: safe close sftp')
            self.safe_close(sftp)
        return ret

    def rm(self, path, level=0):
        def _r(sftp, path, level=0):
            for f in sftp.listdir_attr(path):
                rpath = posixpath.join(path, f.filename)
                if stat.S_ISDIR(f.st_mode):
                    _r(sftp, rpath, level=(level + 1))
                else:
                    logger.debug('rm %s%s', ' ' * level, rpath)
                    sftp.remove(rpath)
            logger.debug('rmdir %s%s', '' * level, path)
            sftp.rmdir(path)

        sftp = self.open_sftp()
        try:
            _r(sftp, path, level)
            ret = True
        except Exception:
            ret = False
        finally:
            logger.debug('rm: safe close sftp')
            self.safe_close(sftp)
        return ret
    # ***************************************************************************************

def test():
    proxy = {
        'host': '11.11.1.2', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p', 'key_path': 'id_rsa'
    }
    client1 = {'host': '11.11.1.3', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    client2 = {'host': '11.11.1.4', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p', 'key_path': '~/.ssh/id_dsa'}
    client3 = {'host': '11.11.1.5', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p', 'key_path': '~/.ssh/id_rsa'}
    client4 = {'host': '11.11.1.6', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}
    client5 = {'host': '11.11.1.7', 'port': 22, 'username': 'vagrant', 'password': 'vagrant', 'auth_type': 'p'}

    pabs = PyABS(proxy)
    pclient5 = PyABS(client5)
    # ===========================================pabs->proxy======================================================
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
            pabs.open_channel()   # must open channel befroe excute cmd
            pabs.exec_command('cd /tmp')
            pabs.exec_command('tar -zcvf test.tar.gz /tmp/*', timeout=60)
            pabs.exec_command('ls /tmp -l')
            # =========================================proxy->client1[t1]=========================================================
            logger.warning('++++++++++++++++proxy->client1[t1]++++++++++++++++')
            pabs.scp(client1, src='/tmp/*.tar.gz', dst='/tmp/')
            pabs.scp(client1, src='/tmp/a.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/b.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/c.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/d.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/e.mp4', dst='/tmp/')
            pabs.scp(client1, src='/tmp/f.mp4', dst='/tmp/')
            t1, code, output = pabs.ssh(client1)
            assert(code == SUCCESS)
            t1.exec_command('ip addr show eth1 && hostname')
            t1.exec_command('ls /tmp/ -l')
            # =========================================client1->client3[t1]=========================================================
            logger.warning('++++++++++++++++client1->client3[t1]++++++++++++++++')
            code, output = t1.scp(client3, src='/tmp/test.tar.gz', dst='/tmp/')
            assert(code == SUCCESS)
            code, output = t1.ssh(client3)
            assert(code == SUCCESS)
            t1.exec_command('ip addr show eth1 && hostname')
            t1.exec_command('ls /tmp/ -l')
            # =========================================proxy->client2[t2]=========================================================
            logger.warning('++++++++++++++++proxy->client2[t2]++++++++++++++++')
            pabs.scp(client2, src='/tmp/*.tar.gz', dst='/tmp/')
            t2, code, output = pabs.ssh(client2)
            assert(code == SUCCESS)
            t2.exec_command('ip addr show eth1 && hostname')
            t2.exec_command('ls /tmp/ -l')

            # =========================================client2->client4[t2]=========================================================
            logger.warning('++++++++++++++++client2->client4[t1]++++++++++++++++')
            code, output = t2.scp(client4, src='/tmp/test.tar.gz', dst='/tmp/')
            assert(code == SUCCESS)
            code, output = t2.ssh(client4)
            assert(code == SUCCESS)
            t2.exec_command('ls /tmp/ -l')
            # ==================================================================================================
            pabs.close()
            # ==================================================================================================
            logger.warning('++++++++++++++++client5++++++++++++++++')
    code, msg = pclient5.login(timeout=3)
    if code == SUCCESS:
        pclient5.mkdir('/tmp/test')
    else:
        logger.debug(msg)
    pclient5.close()

# if __name__ == '__main__':
    # test()
