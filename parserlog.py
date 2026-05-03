import textwrap
import platform
from os import path
from datetime import datetime
from subprocess import run, STDOUT, PIPE

class ParseLog():
    
    def __init__(self, db):
        self.db = db

    def convert_date(self, month, day):
        year = str(datetime.now())[:4]
        if month == "Jun":
            month = "01"
        elif month == "Feb":
            month = "02"
        elif month == "Mar":
            month = "03"
        elif month == "Apr":
            month = "04"
        elif month == "May":
            month = "05"
        elif month == "Jun":
            month = "06"
        elif month == "Jul":
            month = "07"
        elif month == "Aug":
            month = "08"
        elif month == "Sep":
            month = "09"
        elif month == "Oct":
            month = "10"
        elif month == "Nov":
            month = "11"
        elif month == "Dec":
            month = "12"
        day = day.replace(" ", "0")
        date = year+"-"+month+"-"+day
        return date

    def log_secure(self):
        if path.exists("/var/log/secure"):
            cmd = "pkexec cat /var/log/secure*"
        else:
            cmd = "pkexec cat /var/log/auth.log*"
        info_os = platform.freedesktop_os_release()
        # перенаправляем `stdout` и `stderr` в переменную `output`
        output = run(cmd, stdout=PIPE, stderr=STDOUT, text=True, shell=True)
        for i in info_os.values():
            if "debian" in i.lower():
                list = output.stdout.split("\n")
                result_date = []
                result_info = []
                for i in range(len(list)-1):
                    text = textwrap.dedent(list[i][list[i].find(':', 40)+2:]).strip()
                    date = list[i][:10]
                    result_date.append((date))
                    result_info.append((
                                date,
                                list[i][11:19],
                                list[i][40:list[i].find(' ', 40)],
                                textwrap.fill(text, width=120)
                    ))
                break
        else:
            list = output.stdout.split("\n")
            result_date = []
            result_info = []
            for i in range(len(list)-1):
                text = textwrap.dedent(list[i][list[i].find(':', 15)+2:]).strip()
                month = list[i][:3]
                day = list[i][4:6]
                result_date.append((self.convert_date(month, day)))
                result_info.append((
                    self.convert_date(month, day),
                    list[i][7:15],
                    list[i][22:list[i].find(':', 21)],
                    textwrap.fill(text, width=120)
                ))
        self.db.insert_date_db(tuple(set(result_date)))
        self.db.insert_secure_db(result_info)

    def log_BWtmp(self, flag):
        if flag == "wtmp":
            cmd = "last"
            fwb = False
        elif flag == "btmp":
            cmd = "pkexec lastb"
            fwb = True
        output = run(cmd.split(), stdout=PIPE, stderr=STDOUT, text=True)
        list = output.stdout.split("\n")
        result_info = []
        result_date = []
        for i in range(len(list)-1):
            month = list[i][43:46]
            day = list[i][47:49]
            result_date.append((self.convert_date(month, day)))
            result_info.append((
                list[i][:9], 
                list[i][9:22], 
                list[i][22:39],  
                self.convert_date(month, day), 
                list[i][50:63], 
                list[i][64:]
            ))
        self.db.insert_date_db(tuple(set(result_date)))
        self.db.insert_bWtmp_db(result_info, fwb)
