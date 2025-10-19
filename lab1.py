#!/usr/bin/env python3
from dataclasses import asdict, dataclass
import binascii
import hashlib
import json
import os
import sys
from hashlib import pbkdf2_hmac

from Crypto.Cipher import AES
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

DB_PATH = os.path.expanduser("~/.infbez_db.bin")
DB_ENV_KEY = os.environ.get("INFBEZ_DB_KEY", "infbez_secret_key")
AUTHOR_TEXT = "Автор: Чеченев Александр ИДБ-22-10\nИндивидуальное задание: 27 — Несовпадение с именем пользователя, записанным в обратном порядке."

PBKDF2_ITERS = 200000


def _pad(b: bytes) -> bytes:
    pad_len = 16 - (len(b) % 16)
    return b + bytes([pad_len]) * pad_len


def _unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if pad < 1 or pad > 16:
        raise ValueError("Invalid padding")
    return b[:-pad]


def encrypt_bytes(plain: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    iv = bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(_pad(plain))


def decrypt_bytes(data: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    iv = bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(data)
    return _unpad(dec)


def make_password_hash(plain: str, iterations: int = PBKDF2_ITERS):
    salt = os.urandom(16)
    dk = pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
    return binascii.hexlify(dk).decode(), binascii.hexlify(salt).decode(), iterations


def verify_password_hash(stored_hash_hex: str, salt_hex: str, iterations: int, candidate: str):
    try:
        salt = binascii.unhexlify(salt_hex)
        dk = pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, iterations)
        return binascii.hexlify(dk).decode() == stored_hash_hex
    except Exception:
        return False


@dataclass
class User:
    login: str
    password_hash: str = ""
    salt: str = ""
    iterations: int = PBKDF2_ITERS
    restrict: bool = False
    banned: bool = False
    force_change: bool = False


class Database:
    def __init__(self, path: str = DB_PATH, db_key: str = DB_ENV_KEY):
        self.path = path
        self.db_key = db_key
        if not os.path.exists(path):
            self.admin = User("ADMIN", password_hash="", salt="", iterations=PBKDF2_ITERS, restrict=False, banned=False)
            self.users = []
            self._save()
        else:
            self._load()

    def _sanitize_user_dict(self, d: dict) -> dict:
        out = {}
        out["login"] = d.get("login", "")
        out["password_hash"] = d.get("password_hash", d.get("password", ""))
        out["salt"] = d.get("salt", "")
        out["iterations"] = d.get("iterations", PBKDF2_ITERS)
        out["restrict"] = d.get("restrict", False)
        out["banned"] = d.get("banned", False)
        out["force_change"] = d.get("force_change", False)
        return out

    def _save(self):
        obj = {"admin": asdict(self.admin), "users": [asdict(u) for u in self.users]}
        plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        enc = encrypt_bytes(plain, self.db_key)
        with open(self.path, "wb") as f:
            f.write(enc)

    def _load(self):
        with open(self.path, "rb") as f:
            data = f.read()
        try:
            plain = decrypt_bytes(data, self.db_key)
        except Exception:
            QMessageBox.critical(None, "Ошибка", "Не удалось расшифровать файл базы данных. Проверьте ключ.")
            sys.exit(1)
        obj = json.loads(plain.decode("utf-8"))
        a = obj.get("admin", {})
        a = self._sanitize_user_dict(a)
        self.admin = User(**a)
        self.users = []
        for u in obj.get("users", []):
            su = self._sanitize_user_dict(u)
            self.users.append(User(**su))

    def save(self):
        self._save()

    def find_user(self, login: str):
        if login.upper() == "ADMIN":
            return self.admin
        for u in self.users:
            if u.login == login:
                return u
        return None

    def add_user(self, login: str):
        if self.find_user(login) is not None:
            return False
        self.users.append(User(login))
        self._save()
        return True

    def remove_user(self, login: str):
        self.users = [u for u in self.users if u.login != login]
        self._save()


class LoginDialog(QDialog):
    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self.attempts = 0
        self.setWindowTitle("Вход")
        self.resize(340, 140)
        v = QVBoxLayout()
        f1 = QHBoxLayout()
        f1.addWidget(QLabel("Имя:"))
        self.login_edit = QLineEdit()
        f1.addWidget(self.login_edit)
        v.addLayout(f1)
        f2 = QHBoxLayout()
        f2.addWidget(QLabel("Пароль:"))
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        try:
            self.pass_edit.setPasswordCharacter("*")
        except Exception:
            pass
        f2.addWidget(self.pass_edit)
        v.addLayout(f2)
        b = QHBoxLayout()
        self.ok = QPushButton("Вход")
        self.ok.clicked.connect(self.try_login)
        b.addWidget(self.ok)
        self.exitb = QPushButton("Выход")
        self.exitb.clicked.connect(self.reject)
        b.addWidget(self.exitb)
        v.addLayout(b)
        self.setLayout(v)
        self.user = None

    def try_login(self):
        name = self.login_edit.text().strip()
        pwd = self.pass_edit.text()
        if not name:
            QMessageBox.information(self, "Ошибка", "Введите имя пользователя.")
            return
        user = self.db.find_user(name)
        if user is None:
            r = QMessageBox.question(self, "Не найдено", "Пользователь не найден. Повторить ввод?", QMessageBox.Retry | QMessageBox.Close)
            if r == QMessageBox.Close:
                self.reject()
            return
        if user.banned:
            QMessageBox.warning(self, "Заблокирован", "Учетная запись заблокирована.")
            return
        if user.password_hash == "":
            ok = self.force_set_password(user)
            if ok:
                QMessageBox.information(self, "Готово", "Пароль установлен. Пожалуйста, выполните вход с новым паролем.")
                self.pass_edit.clear()
                return
            else:
                return
        if not verify_password_hash(user.password_hash, user.salt, user.iterations, pwd):
            self.attempts += 1
            if self.attempts >= 3:
                QMessageBox.critical(self, "Ошибка", "Три неверных попытки. Работа завершается.")
                self.reject()
                return
            QMessageBox.warning(self, "Неверно", f"Неверный пароль. Попыток: {self.attempts}/3")
            return
        if user.force_change:
            QMessageBox.information(
                self,
                "Внимание",
                "В связи с изменением настроек безопасности для вашей учётной записи сейчас необходимо изменить пароль. После закрытия этого окна откроется форма для установки нового пароля.",
            )
            dlg = ChangePasswordDialog(self.db, user, require_old=True, preverified=True, parent=self)
            if dlg.exec_() == QDialog.Accepted:
                user.force_change = False
                self.db.save()
                self.user = user
                self.accept()
            else:
                QMessageBox.information(self, "Требование", "Требуется смена пароля. Вход отменён.")
                return
        else:
            self.user = user
            self.accept()

    def force_set_password(self, user: User):
        dlg = ChangePasswordDialog(self.db, user, require_old=False, preverified=False, parent=self)
        res = dlg.exec_()
        return res == QDialog.Accepted


class ChangePasswordDialog(QDialog):
    def __init__(self, db: Database, user: User, require_old: bool = True, preverified: bool = False, parent=None):
        super().__init__(parent)
        self.db = db
        self.user = user
        self.require_old = require_old
        self.preverified = preverified
        title = f"Смена пароля ({user.login})"
        self.setWindowTitle(title)
        self.resize(380, 200)
        v = QVBoxLayout()
        if require_old and not preverified:
            f_old = QHBoxLayout()
            f_old.addWidget(QLabel("Старый пароль:"))
            self.old = QLineEdit()
            self.old.setEchoMode(QLineEdit.Password)
            try:
                self.old.setPasswordCharacter("*")
            except Exception:
                pass
            f_old.addWidget(self.old)
            v.addLayout(f_old)
        f_new = QHBoxLayout()
        f_new.addWidget(QLabel("Новый пароль:"))
        self.new = QLineEdit()
        self.new.setEchoMode(QLineEdit.Password)
        try:
            self.new.setPasswordCharacter("*")
        except Exception:
            pass
        f_new.addWidget(self.new)
        v.addLayout(f_new)
        f_conf = QHBoxLayout()
        f_conf.addWidget(QLabel("Повтор:"))
        self.conf = QLineEdit()
        self.conf.setEchoMode(QLineEdit.Password)
        try:
            self.conf.setPasswordCharacter("*")
        except Exception:
            pass
        f_conf.addWidget(self.conf)
        v.addLayout(f_conf)
        self.warn = QLabel("")
        self.warn.setWordWrap(True)
        self.warn.setStyleSheet("color: red;")
        v.addWidget(self.warn)
        h = QHBoxLayout()
        self.ok = QPushButton("ОК")
        self.ok.clicked.connect(self.on_ok)
        self.ok.setEnabled(False)
        h.addWidget(self.ok)
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        h.addWidget(cancel)
        v.addLayout(h)
        self.setLayout(v)
        self.new.textChanged.connect(self._validate)
        self.conf.textChanged.connect(self._validate)
        if require_old and not preverified:
            self.old.textChanged.connect(self._validate)
        self._validate()

    def _validate(self):
        a = self.new.text()
        b = self.conf.text()
        if a != b:
            self.warn.setText("Пароли не совпадают.")
            self.ok.setEnabled(False)
            return
        norm_a = a.strip().lower()
        norm_login_rev = self.user.login.strip()[::-1].lower()
        if self.user.restrict and norm_a == norm_login_rev:
            self.warn.setText("Ограничение: пароль не должен совпадать с именем в обратном порядке.")
            self.ok.setEnabled(False)
            return
        if self.require_old and not self.preverified and getattr(self, "old", None) is not None:
            if self.user.password_hash != "" and not verify_password_hash(self.user.password_hash, self.user.salt, self.user.iterations, self.old.text()):
                self.warn.setText("Старый пароль введён неверно.")
                self.ok.setEnabled(False)
                return
        self.warn.setText("")
        self.ok.setEnabled(True)

    def on_ok(self):
        if self.require_old and not self.preverified:
            if self.user.password_hash != "" and not verify_password_hash(self.user.password_hash, self.user.salt, self.user.iterations, self.old.text()):
                QMessageBox.warning(self, "Ошибка", "Старый пароль неверен.")
                return
        a = self.new.text()
        b = self.conf.text()
        if a != b:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
            return
        if self.user.restrict:
            norm_a = a.strip().lower()
            norm_login_rev = self.user.login.strip()[::-1].lower()
            if norm_a == norm_login_rev:
                QMessageBox.warning(self, "Ограничение", "Пароль не должен совпадать с именем в обратном порядке.")
                return
        h, s, it = make_password_hash(a)
        self.user.password_hash = h
        self.user.salt = s
        self.user.iterations = it
        self.user.force_change = False
        self.db.save()
        self.accept()


class AddUserDialog(QDialog):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("Добавить пользователя")
        self.resize(300, 100)
        v = QVBoxLayout()
        h = QHBoxLayout()
        h.addWidget(QLabel("Имя:"))
        self.name = QLineEdit()
        h.addWidget(self.name)
        v.addLayout(h)
        b = QHBoxLayout()
        ok = QPushButton("Добавить")
        ok.clicked.connect(self.add)
        b.addWidget(ok)
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        b.addWidget(cancel)
        v.addLayout(b)
        self.setLayout(v)

    def add(self):
        n = self.name.text().strip()
        if not n:
            QMessageBox.warning(self, "Ошибка", "Имя пустое.")
            return
        if n.upper() == "ADMIN":
            QMessageBox.warning(self, "Ошибка", "Нельзя добавить ADMIN.")
            return
        if self.db.find_user(n):
            QMessageBox.warning(self, "Ошибка", "Пользователь уже существует.")
            return
        self.db.add_user(n)
        self.accept()


class AdminWindow(QMainWindow):
    def __init__(self, db: Database, admin_user: User):
        super().__init__()
        self.db = db
        self.admin_user = admin_user
        self.setWindowTitle("Администратор")
        self.resize(700, 420)
        central = QWidget()
        self.setCentralWidget(central)
        v = QVBoxLayout()
        central.setLayout(v)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Имя", "Заблок.", "Огран."])
        self.table.setSelectionBehavior(self.table.SelectRows)
        v.addWidget(self.table)
        h = QHBoxLayout()
        addb = QPushButton("Добавить")
        addb.clicked.connect(self.add_user)
        h.addWidget(addb)
        blockb = QPushButton("Блок/Разблок")
        blockb.clicked.connect(self.toggle_block)
        h.addWidget(blockb)
        restrb = QPushButton("Вкл/Выкл огранич.")
        restrb.clicked.connect(self.toggle_restrict)
        h.addWidget(restrb)
        chpass = QPushButton("Сменить пароль")
        chpass.clicked.connect(self.change_password_selected)
        h.addWidget(chpass)
        saveb = QPushButton("Сохранить")
        saveb.clicked.connect(self.save_db)
        h.addWidget(saveb)
        exitb = QPushButton("Выход")
        exitb.clicked.connect(self.close)
        h.addWidget(exitb)
        v.addLayout(h)
        menu = self.menuBar()
        helpm = menu.addMenu("Справка")
        about = QAction("О программе", self)
        about.triggered.connect(lambda: QMessageBox.information(self, "О программе", AUTHOR_TEXT))
        helpm.addAction(about)
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.reload_table()

    def reload_table(self):
        rows = []
        a = self.db.admin
        rows.append({"login": a.login, "banned": a.banned, "restrict": a.restrict})
        for u in self.db.users:
            rows.append({"login": u.login, "banned": u.banned, "restrict": u.restrict})
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(r["login"]))
            self.table.setItem(i, 1, QTableWidgetItem("Да" if r["banned"] else "Нет"))
            self.table.setItem(i, 2, QTableWidgetItem("Да" if r["restrict"] else "Нет"))

    def add_user(self):
        dlg = AddUserDialog(self.db, self)
        if dlg.exec_() == QDialog.Accepted:
            self.reload_table()
            self.status.showMessage("Пользователь добавлен", 3000)

    def _selected_login(self):
        sel = self.table.currentRow()
        if sel < 0:
            QMessageBox.information(self, "Выбор", "Выберите строку.")
            return None
        return self.table.item(sel, 0).text()

    def toggle_block(self):
        name = self._selected_login()
        if not name:
            return
        u = self.db.find_user(name)
        u.banned = not u.banned
        self.db.save()
        self.reload_table()

    def toggle_restrict(self):
        name = self._selected_login()
        if not name:
            return
        u = self.db.find_user(name)
        new = not u.restrict
        u.restrict = new
        if new and u.password_hash != "":
            u.force_change = True
        self.db.save()
        self.reload_table()

    def change_password_selected(self):
        name = self._selected_login()
        if not name:
            return
        u = self.db.find_user(name)
        require_old = False
        if u.login.upper() == "ADMIN":
            require_old = (u.password_hash != "")
        dlg = ChangePasswordDialog(self.db, u, require_old=require_old, preverified=False, parent=self)
        dlg.exec_()
        self.reload_table()

    def save_db(self):
        self.db.save()
        self.status.showMessage("База сохранена", 3000)


class UserWindow(QMainWindow):
    def __init__(self, db: Database, user: User):
        super().__init__()
        self.db = db
        self.user = user
        self.setWindowTitle(f"Пользователь: {user.login}")
        self.resize(420, 160)
        central = QWidget()
        self.setCentralWidget(central)
        v = QVBoxLayout()
        central.setLayout(v)
        ch = QPushButton("Сменить пароль")
        ch.clicked.connect(self.change_password)
        v.addWidget(ch)
        exitb = QPushButton("Выход")
        exitb.clicked.connect(self.close)
        v.addWidget(exitb)
        menu = self.menuBar()
        helpm = menu.addMenu("Справка")
        about = QAction("О программе", self)
        about.triggered.connect(lambda: QMessageBox.information(self, "О программе", AUTHOR_TEXT))
        helpm.addAction(about)
        self.status = QStatusBar()
        self.setStatusBar(self.status)

    def change_password(self):
        dlg = ChangePasswordDialog(self.db, self.user, require_old=True, preverified=False, parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.status.showMessage("Пароль изменен", 3000)


def main():
    app = QApplication(sys.argv)
    db = Database()
    login = LoginDialog(db)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)
    user = login.user
    if user.login.upper() == "ADMIN":
        win = AdminWindow(db, user)
    else:
        win = UserWindow(db, user)
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
