import unittest
import time
from app import create_app, db
from app.models import User


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')  # 建立測試環境
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):  # 設定密碼
        u = User(password='abc')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):  # 驗證是否觸發@property的唯讀屬性
        u = User(password='abc')
        # assertRaises() 用來驗證是否觸發一個特定的 exception。
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verfication(self):  # 驗證密碼比對
        u = User(password='abc')
        self.assertTrue(u.verify_password('abc'))
        self.assertFalse(u.verify_password('123'))

    def test_password_salts_are_random(self): # 驗證不同使用者hash字串部會相等
        u1 = User(password='abc')
        u2 = User(password='abc')
        self.assertTrue(u1.password_hash != u2.password_hash)

    # 驗證token 相關的測試
    def test_valid_confirmation_token(self):  # 測試自己產生的token 是否能通過驗證
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_confirmation_token(self):  # 測試別人的token是否在驗證是會報錯
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))

    def test_expired_confirmation_token(self):  # 測試token過期是否會驗證失敗
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(u.confirm(token))
