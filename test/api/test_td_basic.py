#!/usr/bin/env python
#  -*- coding: utf-8 -*-
import os
import random
import unittest
from test.api.helper import MockInsServer, MockServer
from tqsdk import TqApi, utils


class TestTdBasic(unittest.TestCase):
    """ 验证交易接口的可用性 """

    def setUp(self):
        self.ins = MockInsServer()
        os.environ["TQ_INS_URL"] = f"http://127.0.0.1:{self.ins.port}/t/md/symbols/2020-09-15.json"
        os.environ["TQ_AUTH_URL"] = f"http://127.0.0.1:{self.ins.port}"
        self.mock = MockServer(md_url_character="nfmd")

    def tearDown(self):
        self.ins.close()
        self.mock.close()

    # 模拟交易测试
    def test_insert_order(self):
        """
        下单
        """
        # 预设服务器端响应
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.mock.run(os.path.join(dir_path, "log_file", "test_td_basic_insert_order_simulate.script.lzma"))
        self.md_url = f"ws://127.0.0.1:{self.mock.md_port}/"
        self.td_url = f"ws://127.0.0.1:{self.mock.td_port}/"
        # 测试: 模拟账户下单
        # 非回测, 则需在盘中生成测试脚本: 测试脚本重新生成后，数据根据实际情况有变化,因此需要修改assert语句的内容
        utils.RD = random.Random(4)
        api = TqApi(auth="tianqin,tianqin", _td_url=self.td_url, _md_url=self.md_url)
        order1 = api.insert_order("DCE.jd2101", "BUY", "OPEN", 1)
        order2 = api.insert_order("SHFE.cu2012", "BUY", "OPEN", 2, limit_price=52800)
        while order1.status == "ALIVE" or order2.status == "ALIVE":
            api.wait_update()
        self.assertEqual(order1.order_id, "PYSDK_insert_8ca5996666ceab360512bd1311072231") 
        api.close()

