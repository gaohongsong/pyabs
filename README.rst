自动化运维工具箱 - pyabs
================================

简单介绍：
--------
    基于paramiko开发的python库，支持跨机器SSH认证及跨机器执行命令，认证方式支持密码和密钥认证，支持gevent并发认证。可用于开发自动化运维工具。


使用方法：
-------------
    参考test目录下测测试文件
    1.test.py：直接测试
    2.test_with_celery.py：celery任务测试
    3.test_with_gevent.py：gevent协程测试
