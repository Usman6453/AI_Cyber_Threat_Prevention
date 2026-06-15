import sys
from PyQt6.QtWidgets import QApplication, QLabel

app = QApplication([])
label = QLabel('PyQt test')
label.show()
print('about to exec')
rc = app.exec()
print('exec returned', rc)
