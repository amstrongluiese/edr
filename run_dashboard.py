import ctypes
import multiprocessing
import os

from dashboard.app import main


_INSTANCE_HANDLE = None


def acquire_single_instance() -> bool:
    global _INSTANCE_HANDLE
    if os.name != "nt":
        return True
    _INSTANCE_HANDLE = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\EnterpriseEDRSOCConsole")
    return ctypes.windll.kernel32.GetLastError() != 183


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if acquire_single_instance():
        main()

