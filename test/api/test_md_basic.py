#!/usr/bin/env python
#  -*- coding: utf-8 -*-
import json
import os
import random
import unittest
from datetime import datetime
from test.api.helper import MockInsServer, MockWebsocketsServer
from tqsdk import TqApi, TqBacktest, utils


class TestMdBasic(unittest.TestCase):
    def setUp(self):
        self.ins = MockInsServer()
        os.environ["TQ_INS_URL"] = f"http://127.0.0.1:{self.ins.port}/t/md/symbols/2020-09-15.json"
        os.environ["TQ_AUTH_URL"] = f"http://127.0.0.1:{self.ins.port}"
        self.md_mock = MockWebsocketsServer(url="wss://api.shinnytech.com/t/nfmd/front/mobile")

    def tearDown(self):
        self.ins.close()
        self.md_mock.close()

    # 获取行情测试
    def test_get_quote_normal(self):
        """
        获取行情报价
        """
        # 预设服务器端响应
        utils.RD = random.Random(4)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.md_mock.run(os.path.join(dir_path, "log_file", "test_md_basic_get_quote_normal.script.lzma"))
        md_url = f"ws://127.0.0.1:{self.md_mock.port}/"
        # 获取行情
        api = TqApi(auth="tianqin,tianqin", _md_url=md_url)
        q = api.get_quote("SHFE.cu2101")
        api.close()

    def test_get_kline_serial(self):
        """
        获取K线数据
        """
        # 预设服务器端响应
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.md_mock.run(os.path.join(dir_path, "log_file", "test_md_basic_get_kline_serial.script.lzma"))
        md_url = f"ws://127.0.0.1:{self.md_mock.port}/"
        # 测试: 获取K线数据
        utils.RD = random.Random(4)
        api = TqApi(auth="tianqin,tianqin", _md_url=md_url)
        klines = api.get_kline_serial("SHFE.cu2105", 10)
        self.assertEqual(klines.iloc[-1].close, 58000.0)
        api.close()

    def test_get_tick_serial(self):
        """
        获取tick数据
        """
        # 预设服务器端响应
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.md_mock.run(os.path.join(dir_path, "log_file", "test_md_basic_get_tick_serial.script.lzma"))
        md_url = f"ws://127.0.0.1:{self.md_mock.port}/"
        # 测试: 获取tick数据
        utils.RD = random.Random(4)
        api = TqApi(auth="tianqin,tianqin", _md_url=md_url)
        ticks = api.get_tick_serial("SHFE.cu2105")
        self.assertEqual(ticks.iloc[-1].id, 1314756)
        api.close()
