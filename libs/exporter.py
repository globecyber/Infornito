import os
import csv

def export_csv(destpath, filename, columns, rows):
    if not os.path.exists(destpath):
        os.makedirs(destpath)
    
    with open(os.path.join(destpath,filename), 'w') as outcsv:

        writer = csv.writer(outcsv, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
        writer.writerow(columns)
        for item in rows:
            writer.writerow([sanitize_csv(item[columns[0]]), sanitize_csv(item[columns[1]]), sanitize_csv(item[columns[2]])])


def sanitize_csv(sinput):
    return sinput.replace(',','%2C')