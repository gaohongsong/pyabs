# -*- coding: utf-8 -*-
import random
import time
import gevent
from celery import Celery
from gevent.pool import Pool
from gevent.timeout import Timeout, with_timeout
import sys


class TimeOutException(Exception):
    pass

app = Celery('with_celery', broker='amqp://guest@localhost//')

@app.task
def add(x, y):
    print '%s + %s = %s' % (x, y, x+y)
    return x + y

def sub_task(i):
    c = gevent.getcurrent()
    print '----------> %s' % c
    random.seed(i)
    r = random.randint(0, 5)
    time.sleep(r)
    # gevent.sleep(r)
    print 'sub_task - %s(%ss)' % (i, r)
    return r

@app.task
def test():
    result = []
    start = time.time()

    print 'test start: %s' % start

    try:
        with Timeout(2, TimeOutException) as timeout:
            for t in TaskPool.imap_unordered(sub_task, xrange(10)):
                print t, time.time()
                result.append(t)
    except TimeOutException, e:
        print '*************time out*************'

    end = time.time()
    print 'test end: %s, total: %s' % (end, end - start)
    return result

@app.task
def test_async():
    start = time.time()
    print 'test_async start: %s' % start
    threads = [gevent.spawn(sub_task, i) for i in xrange(10)]
    try:
        gevent.joinall(threads, 3)
        result = [t.value for t in threads if t.successful()]
    except Exception, e:
        print 'test_async exception: %s' % e
    end = time.time()
    print 'test_async end: %s, total: %s' % (end, end - start)
    return result

@app.task
def test_sync():
    start = time.time()
    print 'test start: %s' % start
    result = map(sub_task, xrange(10))
    end = time.time()
    print 'test end: %s, total: %s' % (end, end - start)
    return result

def gsleep(i):
    print 'gsleep: %s' % i
    gevent.sleep(i)
    return i

@app.task
def test_with_timeout():
    try:
        result = with_timeout(1, gsleep, 3)
        # result = with_timeout(1, test_with_timeout, 3, timeout_value=-1)
        print 'test_with_timeout timeout_value = %s' % result
    except Timeout:
        print 'test_with_timeout timout exception'

@app.task
def test_timeout(seconds, default):
    timeout = Timeout.start_new(seconds)
    try:
        try:
            return gsleep(5)
        except Timeout as t:
            # if sys.exc_info()[1] is timeout:
            if t is timeout:
                print 'timeout instance sys.exc_info()[1] is timout: %s' % (sys.exc_info()[1] is timeout)
                return default
            raise  # not my timeout
    finally:
        print 'test_timeout: cancel timeout'
        timeout.cancel()

@app.task
def test_timeout1(seconds, default):
    timeout = gevent.Timeout(seconds)
    timeout.start()
    t = gevent.spawn(gsleep, 1)
    try:
        try:
            t.join(timeout=timeout)
            # started -- Boolean, 指示此Greenlet是否已经启动
            # ready() -- Boolean, 指示此Greenlet是否已经停止
            # successful() -- Boolean, 指示此Greenlet是否已经停止而且没抛异常
            # value -- 任意值, 此Greenlet代码返回的值
            # exception -- 异常, 此Greenlet内抛出的未捕获异常
            if t.successful():
                return t.value
        except Timeout as t:
            # if sys.exc_info()[1] is timeout:
            if t is timeout:
                print 'timeout instance is: %s' % sys.exc_info()[1]
                return default
            print 'test_timeout1: not my timeout'
            raise  # not my timeout
    finally:
        if t.ready():
            print 'greenlet is stop.'
        if t.exception:
            print 'greenlet is stop exception'
        if t.successful():
            print 'greenlet is stop success.'

        print 'test_timeout1: cancel timeout'
        timeout.cancel()


TaskPool = Pool(5)
# celery -A with_celery worker -P gevent -c 10 --logleve=info
if __name__ == '__main__':
    # test()
    add.delay(3, 4)
    # test.delay()
    test_sync.delay()
    test_async.delay()
    test_with_timeout.delay()
    test_timeout.delay(4, -9999)
    test_timeout1.delay(4, -9999)
