import sys
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget
from PyQt5 import QtCore, QtGui, QtWidgets
from loginForm import Ui_Form
from mainWindow import Ui_MainWindow


class LoginForm(QWidget, Ui_Form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.passwordEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.enterButton.clicked.connect(self.enterMethod)
        self.createButton.clicked.connect(self.createMethod)
        mf = MainForm()
        mf.setFixedSize(1000, 600)
        mf.show()

    def enterMethod(self):
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        result = cur.execute(f"""
        SELECT * FROM users
WHERE login = '{self.loginEdit.text()}' AND password = '{self.passwordEdit.text()}'
                            """).fetchall()
        if result:
            self.openMainWindow(self.loginEdit.text(), self.loginEdit.text())

    def createMethod(self):
        con = sqlite3.connect("users.sqlite")
        cur = con.cursor()
        cur.execute(f"""
INSERT INTO users(login, password) VALUES('{self.loginEdit.text()}', '{self.passwordEdit.text()}')
                    """).fetchall()
        con.commit()
        self.openMainWindow(self.loginEdit.text(), self.loginEdit.text())

    def openMainWindow(self, login, password):
        mf = MainForm()
        mf.setFixedSize(1000, 600)
        mf.show()
        #self.close()


class MainForm(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    lf = LoginForm()
    lf.setFixedSize(1000, 600)
    lf.show()
    sys.exit(app.exec())