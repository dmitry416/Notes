import sys
import os
import csv
import shutil
import pyzipper
import hashlib
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, \
    QMessageBox, QInputDialog, QVBoxLayout, QPushButton, QTableWidgetItem
from PyQt5 import QtWidgets
from loginForm import Ui_Form
from mainWindow import Ui_MainWindow


class Account:
    def __init__(self):
        self.Login = None
        self.Password = None
        self.Salt = None


Account = Account()


class HelpfulMethods:
    @staticmethod
    def get_id(login, password):  # получение id пользователя
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        if not cur.execute(f"""
                SELECT password, id FROM users
        WHERE login = '{login}' """).fetchall():
            return -1, None
        storage, id = cur.execute(f"""
                SELECT password, id FROM users
        WHERE login = '{login}' """).fetchall()[0]
        con.close()
        storage = bytes.fromhex(storage)
        if HelpfulMethods.get_hash(storage[:32], password) == storage[32:]:
            return id, storage[:32]
        return -1, None

    @staticmethod
    def is_correct_password(password):  # проверка на правильность пароля
        if password.isalnum():
            if len(password) >= 5:
                return True
        return False

    @staticmethod
    def throw_message(title, text, buttons=False):  # диалоговое окно
        mb = QMessageBox()
        mb.setWindowTitle(title)
        mb.setText(text)
        if buttons:
            mb.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            mb.setDefaultButton(QMessageBox.No)
        return mb.exec()

    @staticmethod
    def get_hash(salt, text):  # получение хэша
        return hashlib.pbkdf2_hmac('sha256', text.encode('utf-8'), salt, 100000)

    @staticmethod
    def make_zip(name, password, delete=False):  # создание zip с паролем
        if not delete:
            os.chdir(f'.\\data\\')
            with pyzipper.AESZipFile(f'{name}.zip', 'w',
                                     compression=pyzipper.ZIP_LZMA,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(bytes(password, 'utf-8'))
                os.chdir(f'.\\{name}')
                for f in os.listdir():
                    zf.write(f)
                os.chdir('../')
            os.chdir('../')

        shutil.rmtree(f'{os.path.abspath(__file__)[:-7]}data\\{name}\\')

    @staticmethod
    def make_unzip(name, password): # распаковка zip с паролем
        os.chdir(f'.\\data\\')
        with pyzipper.AESZipFile(name, 'r', compression=pyzipper.ZIP_LZMA,
                                 encryption=pyzipper.WZ_AES) as z:
            z.setpassword(bytes(password, 'utf-8'))
            z.extractall(name[:-4])
        os.remove(name)
        os.chdir('../')


class LoginForm(QWidget, Ui_Form):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Notes')
        self.setupUi(self)
        self.passwordEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.enterButton.clicked.connect(self.enterMethod)
        self.createButton.clicked.connect(self.createMethod)

    def enterMethod(self):
        id, Account.Salt = HelpfulMethods.get_id(self.loginEdit.text(), self.passwordEdit.text())
        if id != -1:
            Account.Login = self.loginEdit.text()
            Account.Password = self.passwordEdit.text()
            self.openMainWindow(id)
        else:
            self.wrongPassword()

    def wrongPassword(self):
        self.passwordEdit.setText('')
        HelpfulMethods.throw_message('Ошибка', 'Неверный логин или пароль.')

    def createMethod(self):
        if not HelpfulMethods.is_correct_password(self.loginEdit.text()):
            self.passwordEdit.setText('')
            m = 'Логин может состоять только из букв и цифр, и быть не меньше 5 символов.'
            HelpfulMethods.throw_message('Неверный формат логина', m)
            return
        if not HelpfulMethods.is_correct_password(self.passwordEdit.text()):
            self.passwordEdit.setText('')
            m = 'Пароль может состоять только из букв и цифр, и быть не меньше 5 символов.'
            HelpfulMethods.throw_message('Неверный формат пароля', m)
            return
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        m = f"""SELECT * FROM users WHERE login = '{self.loginEdit.text()}'"""
        login = cur.execute(m).fetchall()
        if login:
            self.passwordEdit.setText('')
            HelpfulMethods.throw_message('Неверный формат логина', 'Такой логин уже существует.')
            return
        Account.Salt = os.urandom(32)
        cur.execute(f"""
INSERT INTO users(login, password) VALUES('{self.loginEdit.text()}', '{(Account.Salt + 
                                                                        HelpfulMethods.get_hash(
            Account.Salt, self.passwordEdit.text())).hex()}')
""").fetchall()
        Account.Login = self.loginEdit.text()
        Account.Password = self.passwordEdit.text()
        con.commit()
        self.openMainWindow(HelpfulMethods.get_id(self.loginEdit.text(),
                                                  self.passwordEdit.text())[0])
        con.close()

    def openMainWindow(self, id):  # открытие основного окна
        self._mf = MainForm(id)
        self._mf.setFixedSize(1015, 600)
        self._mf.show()
        self._mf.setWindowTitle('Секретные записи')
        self.close()


class MainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, id):
        super().__init__()
        self.path = os.path.abspath(__file__)[:-7] + 'data\\'
        if not os.path.exists(os.path.abspath(__file__)[:-7] + 'data\\'):
            os.mkdir(os.path.abspath(__file__)[:-7] + 'data')
        self.setupUi(self)
        self.id = id
        self.hexhashlogin = HelpfulMethods.get_hash(Account.Salt, Account.Login).hex()
        self.curButton = None
        self.leaveButton.clicked.connect(self.leaveMethod)
        self.changeLoginButton.clicked.connect(self.changeLoginMethod)
        self.changePasswordButton.clicked.connect(self.changePasswordMethod)
        self.saveButton.clicked.connect(self.saveMethod)
        self.deleteButton.clicked.connect(self.deleteMethod)
        self.deleteAccountButton.clicked.connect(self.deleteAccountMethod)

        self.createTable.clicked.connect(self.createTableMethod)
        self.saveTable.clicked.connect(self.saveTableMethod)

        if os.path.exists(os.path.abspath(__file__)[:-7] + 'data\\' + self.hexhashlogin + '.zip'):
            HelpfulMethods.make_unzip(self.hexhashlogin + '.zip', Account.Password)
        self.updateScroll()

    def createTableMethod(self):
        rows_count, ok_pressed1 = QInputDialog.getInt(self, "Введите данные",
                                                      "Количество строк", 1, 1)
        if not ok_pressed1:
            return
        cols_count, ok_pressed2 = QInputDialog.getInt(self, "Введите данные",
                                                      "Количество столбцов", 1, 1)
        if ok_pressed1 and ok_pressed2:
            self.tableWidget.setRowCount(rows_count)
            self.tableWidget.setColumnCount(cols_count)

    def saveTableMethod(self):
        if self.curButton and self.curButton.text()[-4:] == '.csv':
            with open(self.path +
                      f'{self.hexhashlogin}\\{self.curButton.text()[3:]}', 'wt', newline='') \
                    as csvfile:
                writer = csv.writer(
                    csvfile, delimiter=';', quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)
                for i in range(self.tableWidget.rowCount()):
                    row = []
                    for j in range(self.tableWidget.columnCount()):
                        item = self.tableWidget.item(i, j)
                        if item is not None:
                            row.append(item.text())
                    writer.writerow(row)
            self.tableWidget.setRowCount(0)
            self.tableWidget.setColumnCount(0)
            self.plainTextEdit.setPlainText('')
            self.curButton = None
            self.updateScroll()
            return
        if not (self.tableWidget.columnCount() and self.tableWidget.rowCount()):
            return 
        name, ok_pressed = QInputDialog.getText(self, "Введите название", "Название файла.")
        if ok_pressed:
            with open(self.path + f'{self.hexhashlogin}\\{name}.csv', 'wt', newline='') as csvfile:
                writer = csv.writer(
                    csvfile, delimiter=';', quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)
                for i in range(self.tableWidget.rowCount()):
                    row = []
                    for j in range(self.tableWidget.columnCount()):
                        item = self.tableWidget.item(i, j)
                        if item is not None:
                            row.append(item.text())
                    writer.writerow(row)
            self.tableWidget.setRowCount(0)
            self.tableWidget.setColumnCount(0)
            self.plainTextEdit.setPlainText('')
        self.updateScroll()

    def deleteMethod(self):
        if self.curButton:
            result = HelpfulMethods.throw_message('Внимание',
                                                  'Вы действительно хотите удалить файл?', True)
            if result == QMessageBox.No:
                return
            os.remove(self.path + f'{self.hexhashlogin}\\{self.curButton.text()[3:]}')
            self.curButton = None
            self.updateScroll()
        else:
            result = HelpfulMethods.throw_message('Внимание',
                                                  'Вы действительно хотите удалить запись?', True)
            if result == QMessageBox.No:
                return
        self.plainTextEdit.setPlainText('')

    def updateScroll(self):  # метод обновляет scrollarea с кнопками
        if not os.path.exists(self.path + f'{self.hexhashlogin}'):
            os.mkdir(self.path + f'{self.hexhashlogin}')
        self.widget = QWidget()
        self.vbox = QVBoxLayout()

        for name in os.listdir(self.path + f'{self.hexhashlogin}'):
            b = QPushButton(self)
            b.setText(name)
            b.setMinimumHeight(40)
            b.clicked.connect(self.fileButtonBehaviour)
            self.vbox.addWidget(b)
            if self.curButton:
                if b.text() == self.curButton.text()[3:]:
                    self.curButton = b
                    self.curButton.setText('>> ' + self.curButton.text())
        self.widget.setLayout(self.vbox)
        self.scrollArea.setWidget(self.widget)

    def fileButtonBehaviour(self):  # определяет поведение кнопки после нажатия
        button = self.sender()
        if self.curButton:
            if self.curButton == button:
                self.curButton = None
                button.setText(button.text()[3:])
                self.plainTextEdit.setPlainText("")
                self.tableWidget.setRowCount(0)
                self.tableWidget.setColumnCount(0)
                self.tabWidget.setTabEnabled(1, True)
                return
            self.curButton.setText(self.curButton.text()[3:])
        self.curButton = button
        self.curButton.setText('>> ' + self.curButton.text())
        with open(self.path + f'{self.hexhashlogin}/{self.curButton.text()[3:]}', 'rt') as f:
            self.plainTextEdit.setPlainText(f.read())
        if self.curButton.text()[-4:] == '.csv':
            self.tabWidget.setTabEnabled(1, True)
            with open(self.path +
                      f'{self.hexhashlogin}\\{self.curButton.text()[3:]}', encoding="utf8")\
                    as csvfile:
                reader = list(csv.reader(csvfile, delimiter=';', quotechar='"'))
                title = reader[0]
                self.tableWidget.setColumnCount(len(title))
                self.tableWidget.setHorizontalHeaderLabels(list(map(str,
                                                                    range(1, len(title) + 1))))
                self.tableWidget.setRowCount(0)
                for i, row in enumerate(reader):
                    self.tableWidget.setRowCount(
                        self.tableWidget.rowCount() + 1)
                    for j, elem in enumerate(row):
                        self.tableWidget.setItem(
                            i, j, QTableWidgetItem(elem))
            self.tableWidget.resizeColumnsToContents()
        else:
            self.tabWidget.setTabEnabled(1, False)

    def saveMethod(self):
        if self.curButton:
            text = self.plainTextEdit.toPlainText()
            with open(self.path + f'{self.hexhashlogin}\\{self.curButton.text()[3:]}', 'wt') as f:
                f.write(text)
            self.plainTextEdit.setPlainText('')
            self.curButton = None
            self.updateScroll()
            return
        name, ok_pressed = QInputDialog.getText(self, "Введите название", "Название файла.")
        if ok_pressed:
            text = self.plainTextEdit.toPlainText()
            with open(self.path + f'{self.hexhashlogin}\\{name}.txt', 'wt') as f:
                f.write(text)
            self.plainTextEdit.setPlainText('')
        self.updateScroll()

    def leaveMethod(self, delete=False):
        if os.path.exists(os.path.abspath(__file__)[:-7] + 'data\\' + self.hexhashlogin):
            HelpfulMethods.make_zip(self.hexhashlogin, Account.Password, delete)
        self._lf = LoginForm()
        self._lf.setFixedSize(1015, 600)
        self._lf.show()
        self._lf.setWindowTitle('Секретные записи')
        self.close()

    def changeLoginMethod(self):
        login, ok_pressed = QInputDialog.getText(self, "Новый логин", "Введите новый логин.")
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        m = f"""SELECT * FROM users WHERE login = '{login}'"""
        if cur.execute(m).fetchall():
            HelpfulMethods.throw_message('Неверный формат логина', 'Такой логин уже существует.')
            return
        if ok_pressed:
            if not HelpfulMethods.is_correct_password(login):
                m = 'Логин может состоять только из букв и цифр, и быть не меньше 5 символов.'
                HelpfulMethods.throw_message('Неверный формат логина', m)
                return
            con = sqlite3.connect("users.sqlite")
            cur = con.cursor()
            cur.execute(f"""UPDATE users SET login = '{login}' WHERE id = {self.id}""").fetchall()
            con.commit()
            con.close()
            old_login = self.hexhashlogin
            self.hexhashlogin = (HelpfulMethods.get_hash(Account.Salt, login)).hex()
            os.rename(self.path + f'{old_login}', self.path + self.hexhashlogin)

    def changePasswordMethod(self):
        password, ok_pressed = QInputDialog.getText(self, "Новый пароль", "Введите новый пароль.")
        if ok_pressed:
            if not HelpfulMethods.is_correct_password(password):
                m = 'Пароль может состоять только из букв и цифр, и быть не меньше 5 символов.'
                HelpfulMethods.throw_message('Неверный формат пароля', m)
                return
            con = sqlite3.connect("users.sqlite")
            cur = con.cursor()
            cur.execute(f"""UPDATE users SET password = '{(Account.Salt + HelpfulMethods.get_hash(
            Account.Salt, password)).hex()}' WHERE id = {self.id}""").fetchall()
            con.commit()
            con.close()
            Account.Password = password

    def deleteAccountMethod(self):
        result = HelpfulMethods.throw_message('Внимание',
                                              'Вы действительно хотите удалить аккаунт?', True)
        if result == QMessageBox.Yes:
            con = sqlite3.connect("users.sqlite")
            cur = con.cursor()
            cur.execute(f"""DELETE FROM users WHERE id = {self.id}""").fetchall()
            con.commit()
            con.close()
            self.leaveMethod(True)


if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        lf = LoginForm()
        lf.setFixedSize(1015, 600)
        lf.show()
        lf.setWindowTitle('Секретные записи')
        sys.exit(app.exec())
    except:
        if Account.Salt and Account.Login:
            hash = HelpfulMethods.get_hash(Account.Salt, Account.Login).hex()
            if os.path.exists(os.path.abspath(__file__)[:-7] + 'data\\' + hash):
                HelpfulMethods.make_zip(hash, Account.Password)
