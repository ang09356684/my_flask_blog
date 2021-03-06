import os
from flask_migrate import Migrate
from app import create_app, db
from app.models import User, Role, Permission

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
migrate = Migrate(app, db)


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Permission=Permission)


@app.cli.command()  # 將被裝飾的函式名稱當作執行命令的名稱
def test():
    """Run the unit tests."""  # 顯示再說明的內容
    import unittest
    tests = unittest.TestLoader().discover('tests')  # 測試探索指定資料夾
    unittest.TextTestRunner(verbosity=2).run(tests) # verbosity 調整執行測試時所輸出的細節。
