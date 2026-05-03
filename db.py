import sqlite3 as sql

class DB:
    def __init__(self, path):
        self.password = None
        self.enc_path = None
        self.temp_path = None
        if path != "":
            self.db = sql.connect(path)
            self.cursor = self.db.cursor()
            self.cursor.execute("""CREATE TABLE IF NOT EXISTS date(
                                id_date INTEGER PRIMARY KEY AUTOINCREMENT,
                                date TEXT
            )""")
            self.cursor.execute("""CREATE TABLE IF NOT EXISTS authInfo(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                date_id INTEGER,
                                time TEXT,
                                proc TEXT,
                                desc TEXT,
                                FOREIGN KEY (date_id) REFERENCES date (id_date)
            )""")
            self.cursor.execute("""CREATE TABLE IF NOT EXISTS btmp_wtmpInfo(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user TEXT,
                                tty TEXT,
                                host TEXT,
                                date_id INTEGER,
                                time TEXT,
                                session TEXT,
                                flag BOOL,
                                FOREIGN KEY (date_id) REFERENCES date (id_date)
            )""")
            self.cursor.execute("""CREATE VIEW IF NOT EXISTS wtmp_with_date AS
                                SELECT
                                    btmp_wtmpInfo.user AS user,
                                    btmp_wtmpInfo.tty AS tty,
                                    btmp_wtmpInfo.host AS host,
                                    date.date AS date,
                                    btmp_wtmpInfo.time AS time,
                                    btmp_wtmpInfo.session AS session 
                                FROM btmp_wtmpInfo
                                    INNER JOIN date
                                    ON btmp_wtmpInfo.date_id = date.id_date
                                WHERE btmp_wtmpInfo.FLAG = 0
            """)
            self.cursor.execute("""CREATE VIEW IF NOT EXISTS btmp_with_date AS
                                SELECT
                                    btmp_wtmpInfo.user AS user,
                                    btmp_wtmpInfo.tty AS tty,
                                    btmp_wtmpInfo.host AS host,
                                    date.date AS date,
                                    btmp_wtmpInfo.time AS time,
                                    btmp_wtmpInfo.session AS session 
                                FROM btmp_wtmpInfo
                                    INNER JOIN date
                                    ON btmp_wtmpInfo.date_id = date.id_date
                                WHERE btmp_wtmpInfo.FLAG = 1
            """)
            self.cursor.execute("""CREATE VIEW IF NOT EXISTS authInfo_with_date AS
                                SELECT
                                    date.date AS date,
                                    authInfo.time AS time,
                                    authInfo.proc AS proc,
                                    authInfo.desc AS desc
                                FROM authInfo
                                    INNER JOIN date
                                    ON authInfo.date_id = date.id_date
            """)
            self.db.commit()
        else:
            print("Not path for DB")

    def insert_secure_db(self, info_list):
        for i in range(len(info_list)-2):
            self.cursor.execute(f"SELECT id_date FROM date WHERE  date = ('{info_list[i][0]}')")
            id_date = self.cursor.fetchone()
            self.cursor.execute("INSERT INTO authInfo (date_id, time, proc, desc) VALUES (?,?,?,?)", (int(id_date[0]), info_list[i][1], info_list[i][2], info_list[i][3]))
        self.cursor.execute("DELETE FROM authInfo WHERE rowid NOT IN (SELECT MIN(rowid) FROM authInfo GROUP BY date_id, time, proc, desc);")
        self.db.commit()

    def insert_bWtmp_db(self, info_list, flag):
        for i in range(len(info_list)-2):
            self.cursor.execute(f"SELECT id_date FROM date WHERE date = ('{info_list[i][3]}')")
            id_date = self.cursor.fetchone()
            self.cursor.execute(f"INSERT INTO btmp_wtmpInfo (user, tty, host, date_id, time, session, flag) VALUES (?, ?, ?, ?, ?, ?, ?)", (info_list[i][0],info_list[i][1],info_list[i][2], int(id_date[0]),info_list[i][4], info_list[i][5], flag))
        self.cursor.execute("DELETE FROM btmp_wtmpInfo WHERE rowid NOT IN (SELECT MIN(rowid) FROM btmp_wtmpInfo GROUP BY user, tty, host, date_id, time, session, flag);")
        self.db.commit()
        
    def insert_date_db(self, info_list):
        for i in range(len(info_list)):
            self.cursor.execute(f"INSERT INTO date (date) VALUES ('{info_list[i]}')")
        self.cursor.execute("DELETE FROM date  WHERE rowid NOT IN (SELECT MIN(rowid) FROM date GROUP BY date);")
        self.db.commit()

    def close_db(self):
        self.cursor.close()
        self.db.close()
        