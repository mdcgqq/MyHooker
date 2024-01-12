import sqlite3
import os

db_dir = "/Users/lihuaqi/MyPlace/codeHouse/frida/files/逆向过程记录/8230/databases/"
for file in os.listdir(db_dir):
    if (file.endswith(".db")):
        db_file_path = db_dir + file

        try:
            conn = sqlite3.connect(db_file_path)
            print("connect " + db_file_path)
            c = conn.cursor()

            tables = []

            cursor = c.execute("SELECT name FROM sqlite_master WHERE type='table';")
            for row in cursor:
                table_name = row[0]
                tables.append(table_name)

            for table_name in tables:
                print("TABLE_NAME " + table_name)
                cursor2 = c.execute("SELECT * FROM " + table_name + ";")
                for row in cursor2:
                    print(row)

            conn.close()
            print("close " + db_file_path)
        except Exception as e:
            pass
