from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from . import db
from .models import User, Post


def users(count=100):  # 透過Faker建立一百名使用者的假資料
    fake = Faker('zh_TW', 'ja_JP', 'en_US')
    i = 0
    while i < count:
        user = User(email=fake.email(),
                 username=fake.user_name(),
                 password='password',
                 confirmed=True,
                 name=fake.name(),
                 location=fake.city(),
                 about_me=fake.text(),
                 member_since=fake.past_date())
        db.session.add(user)
        try:
            # 因為email 和username 是隨機產生
            db.session.commit()
            i += 1
        except IntegrityError:  # 若發生重複會報錯誤
            db.session.rollback() # 回復session 取消重複的使用者


def posts(count=100):  # 創建假文章
    fake = Faker('zh_TW', 'ja_JP', 'en_US')
    user_count = User.query.count()
    for i in range(count):
        # 用offset掉隨機整數 取得user 再指派給文章 建立關聯
        user = User.query.offset(randint(0, user_count - 1)).first()
        post = Post(body=fake.text(),
                 timestamp=fake.past_date(),
                 author=user)
        db.session.add(post)
    db.session.commit()
