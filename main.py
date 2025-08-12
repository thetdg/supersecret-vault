#!/usr/bin/env python3
# SuperSecret Vault - PyQt6 GUI Version
# Author: Tanmoy Dasgupta (https://github.com/thetdg)

import sys
import os
import subprocess
import concurrent.futures
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QLineEdit, QLabel, QProgressBar, QMessageBox, QInputDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


VERSION = "1.0"


class FileProcessorThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(int, int, int)

    def __init__(self, folder_name, password, operation):
        super().__init__()
        self.folder_name = folder_name
        self.password = password
        self.operation = operation

    def process_file(self, file_path):
        try:
            file_type = subprocess.check_output(["file", "-b", str(file_path)]).decode().split()[0]
        except Exception:
            file_type = ""

        if self.operation == "encrypt":
            if file_type not in ("GPG", "PGP"):
                result = subprocess.run(
                    ["gpg", "--batch", "-c", "--compress-algo", "none", "--passphrase-fd", "0", str(file_path)],
                    input=self.password.encode(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    os.remove(file_path)
                    return "success"
                else:
                    return "skipped"
            else:
                return "skipped"

        elif self.operation == "decrypt":
            if file_type in ("GPG", "PGP"):
                output_path = file_path.with_suffix("")
                tmp_output_path = output_path.with_suffix(".tmp")
                with open(tmp_output_path, "wb") as tmp_out:
                    result = subprocess.run(
                        ["gpg", "-d", "--batch", "--yes", "--passphrase-fd", "0", str(file_path)],
                        input=self.password.encode(),
                        stdout=tmp_out,
                        stderr=subprocess.DEVNULL
                    )
                if result.returncode == 0:
                    os.remove(file_path)
                    os.rename(tmp_output_path, output_path)
                    return "success"
                else:
                    os.remove(tmp_output_path)
                    return "skipped"
            else:
                return "skipped"
        return "skipped"

    def run(self):
        files = list(Path(self.folder_name).rglob("*"))
        files = [f for f in files if f.is_file()]
        total_files = len(files)
        processed = success = skipped = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = {executor.submit(self.process_file, file_path): file_path for file_path in files}
            for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                result = future.result()
                processed += 1
                if result == "success":
                    success += 1
                else:
                    skipped += 1
                percent = int((processed / total_files) * 100)
                self.progress_signal.emit(percent)

        self.result_signal.emit(processed, success, skipped)


class SuperSecretVaultGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.folder_name = ""
        self.password = ""
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"SuperSecret Vault v{VERSION}")
        self.setFixedSize(300, 400)

        layout = QVBoxLayout()

        self.label = QLabel("No vault selected", self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

        btn_select_vault = QPushButton("Create / Open Vault")
        btn_select_vault.clicked.connect(self.create_vault)
        layout.addWidget(btn_select_vault)

        btn_encrypt = QPushButton("Encrypt Files")
        btn_encrypt.clicked.connect(lambda: self.process_files("encrypt"))
        layout.addWidget(btn_encrypt)

        btn_decrypt = QPushButton("Decrypt Files")
        btn_decrypt.clicked.connect(lambda: self.process_files("decrypt"))
        layout.addWidget(btn_decrypt)

        self.progress = QProgressBar(self)
        layout.addWidget(self.progress)

        btn_quit = QPushButton("Quit")
        btn_quit.clicked.connect(self.close)
        layout.addWidget(btn_quit)

        self.setLayout(layout)

    def create_vault(self):
        folder = QFileDialog.getExistingDirectory(self, "Select or Create Vault Folder")
        if folder:
            Path(folder).mkdir(parents=True, exist_ok=True)
            self.folder_name = folder
            self.label.setText(f"Vault: {folder}")

    def prompt_password(self, confirm=False):
        if confirm:
            while True:
                pwd, ok = QInputDialog.getText(self, "Password", "Enter Vault Password:", QLineEdit.EchoMode.Password)
                if not ok:
                    return None
                pwd2, ok2 = QInputDialog.getText(self, "Confirm Password", "Re-enter Vault Password:", QLineEdit.EchoMode.Password)
                if not ok2:
                    return None
                if pwd == pwd2:
                    return pwd
                QMessageBox.warning(self, "Error", "Passwords do not match. Try again.")
        else:
            pwd, ok = QInputDialog.getText(self, "Password", "Enter Vault Password:", QLineEdit.EchoMode.Password)
            return pwd if ok else None

    def process_files(self, operation):
        if not self.folder_name:
            QMessageBox.warning(self, "Error", "No vault selected!")
            return

        if operation == "encrypt":
            password = self.prompt_password(confirm=True)
        else:
            password = self.prompt_password(confirm=False)

        if not password:
            return

        files = list(Path(self.folder_name).rglob("*"))
        files = [f for f in files if f.is_file()]
        total_files = len(files)

        if total_files == 0:
            QMessageBox.information(self, "Info", "No files found in the vault.")
            return

        self.progress.setValue(0)
        self.thread = FileProcessorThread(self.folder_name, password, operation)
        self.thread.progress_signal.connect(self.progress.setValue)
        self.thread.result_signal.connect(self.show_result)
        self.thread.start()

    def show_result(self, processed, success, skipped):
        QMessageBox.information(self, "Done",
                                f"Files processed: {processed}\n"
                                f"Files successfully processed: {success}\n"
                                f"Files skipped: {skipped}")


def main():
    app = QApplication(sys.argv)
    gui = SuperSecretVaultGUI()
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
