"""Print the computer name recorded in a SYSTEM hive. Runs inside the Plaso container, which ships pyregf.

Usage: python3 computer_name.py <SYSTEM hive>
"""
import sys

import pyregf

hive = pyregf.file()
hive.open(sys.argv[1])
root = hive.get_root_key()
select = root.get_sub_key_by_path("Select")
current = select.get_value_by_name("Current").get_data_as_integer() if select else 1
key = root.get_sub_key_by_path(f"ControlSet{current:03d}\\Control\\ComputerName\\ComputerName")
print(key.get_value_by_name("ComputerName").get_data_as_string())
