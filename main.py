import sys
import os
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, \
    QMessageBox, QInputDialog, QVBoxLayout, QPushButton
from PyQt5 import QtWidgets, QtCore
from loginForm import Ui_Form
from mainWindow import Ui_MainWindow


class LoginForm(QWidget, Ui_Form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.passwordEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.enterButton.clicked.connect(self.enterMethod)
        self.createButton.clicked.connect(self.createMethod)

    def enterMethod(self):
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        result = cur.execute(f"""
        SELECT id FROM users
WHERE login = '{self.loginEdit.text()}' AND password = '{self.passwordEdit.text()}'
                            """).fetchall()
        if result:
            self.openMainWindow(result[0][0])
        else:
            self.wrongPassword()
        con.close()

    def wrongPassword(self):
        self.passwordEdit.setText('')
        mb = QMessageBox()
        mb.setWindowTitle('Ошибка')
        mb.setText('Неверный логин или пароль.')
        mb.exec()

    @staticmethod
    def isCorrect(data):
        if data.isalnum():
            if len(data) >= 5:
                return True
        return False

    def createMethod(self):
        if not self.isCorrect(self.loginEdit.text()):
            self.passwordEdit.setText('')
            mb = QMessageBox()
            mb.setWindowTitle('Неверный формат логина')
            mb.setText('Логин может состоять только из букв и цифр, и быть не меньше 5 символов.')
            mb.exec()
            return
        if not self.isCorrect(self.passwordEdit.text()):
            self.passwordEdit.setText('')
            mb = QMessageBox()
            mb.setWindowTitle('Неверный формат пароля')
            mb.setText('Пароль может состоять только из букв и цифр, и быть не меньше 5 символов.')
            mb.exec()
            return
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        cur.execute(f"""
INSERT INTO users(login, password) VALUES('{self.loginEdit.text()}', '{self.passwordEdit.text()}')
                    """).fetchall()
        con.commit()
        id = cur.execute(f"""
SELECT id FROM users
WHERE login = '{self.loginEdit.text()}' AND password = '{self.passwordEdit.text()}'
                    """).fetchall()
        self.openMainWindow(id[0][0])
        con.close()

    def openMainWindow(self, id):
        self._mf = MainForm(id)
        self._mf.setFixedSize(1000, 600)
        self._mf.show()
        self.close()


class MainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, id):
        super().__init__()
        self.setupUi(self)
        self.updateScroll()
        self.id = id
        self.curButton = None
        self.leaveButton.clicked.connect(self.leaveMethod)
        self.changeLoginButton.clicked.connect(self.changeLoginMethod)
        self.changePasswordButton.clicked.connect(self.changePasswordMethod)
        self.saveButton.clicked.connect(self.saveMethod)
        #self.deleteButton.clicked.connect()
        self.deleteAccountButton.clicked.connect(self.deleteAccountMethod)

    def updateScroll(self):
        self.widget = QWidget()
        self.vbox = QVBoxLayout()

        for name in os.listdir(f'/data/{login}'):
            b = QPushButton(self)
            b.setText(name[:-3])
            b.setMinimumHeight(40)
            b.clicked.connect()
            self.vbox.addWidget(b)

        self.widget.setLayout(self.vbox)
        self.scrollArea.setWidget(self.widget)

    def saveMethod(self):
        name, ok_pressed = QInputDialog.getText(self, "Введите название",
                                                "Название файла.")
        if ok_pressed:
            text = self.plainTextEdit.toPlainText()
            with open(f'data/{login}/{name}.txt', 'wt') as f:
                f.write(text)


    def leaveMethod(self):
        self._lf = LoginForm()
        self._lf.setFixedSize(1000, 600)
        self._lf.show()
        self.close()

    def changeLoginMethod(self):
        login, ok_pressed = QInputDialog.getText(self, "Новый логин", "Введите новый логин.")
        if ok_pressed:
            if not LoginForm.isCorrect(login):
                mb = QMessageBox()
                mb.setWindowTitle('Неверный формат логина')
                mb.setText('Логин может состоять только из букв и цифр, и быть не меньше 5 символов.')
                mb.exec()
                return
            con = sqlite3.connect("users.sqlite")
            cur = con.cursor()
            cur.execute(f"""
                    UPDATE users
            SET login = '{login}'
            WHERE id = {self.id}
                                        """).fetchall()
            con.commit()
            con.close()

    def changePasswordMethod(self):
        password, ok_pressed = QInputDialog.getText(self, "Новый пароль", "Введите новый пароль.")
        if ok_pressed:
            if not LoginForm.isCorrect(password):
                mb = QMessageBox()
                mb.setWindowTitle('Неверный формат пароля')
                mb.setText('Пароль может состоять только из букв и цифр, и быть не меньше 5 символов.')
                mb.exec()
                return
            con = sqlite3.connect("users.sqlite")
            cur = con.cursor()
            cur.execute(f"""
                    UPDATE users
            SET password = '{password}'
            WHERE id = {self.id}
                                        """).fetchall()
            con.commit()
            con.close()

    def deleteAccountMethod(self):
        mb = QMessageBox()
        mb.setText('Вы действительно хотите удалить аккаунт?')
        mb.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        mb.setDefaultButton(QMessageBox.No)
        result = mb.exec()
        if result == QMessageBox.Yes:
            con = sqlite3.connect("users.sqlite")
            cur = con.cursor()
            cur.execute(f"""
                                DELETE FROM users
                        WHERE id = {self.id}
                                                    """).fetchall()
            con.commit()
            con.close()
            self.leaveMethod()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    lf = LoginForm()
    lf.setFixedSize(1000, 600)
    lf.show()
    sys.exit(app.exec())
