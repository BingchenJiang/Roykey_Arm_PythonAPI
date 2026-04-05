import sys

from PyQt5.QtWidgets import QApplication, QMessageBox, QMainWindow

from dongle_auth_ras1 import check_dongle_secure

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 核心拦截逻辑：在此处卡住程序启动
    if not check_dongle_secure():
        QMessageBox.critical(
            None,
            "安全验证失败",
            "未检测到合法的授权加密狗，或者加密狗版本不匹配。\n\n请插入正确的 USB 加密狗后重新启动程序。"
        )
        sys.exit(1)  # 强制退出，不加载主界面

    # 如果代码走到这里，说明验证通过，正常加载你的主程序
    main_window = QMainWindow()
    main_window.setWindowTitle("主程序")
    main_window.resize(800, 600)
    main_window.show()

    sys.exit(app.exec_())
