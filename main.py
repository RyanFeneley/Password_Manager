"""
main.py
Author: Ryan Feneley
Date: September 2024
"""

from gui_interface import start_gui
from db import Database

def main():
    db = Database()
    start_gui()

if __name__ == "__main__":
    main()
