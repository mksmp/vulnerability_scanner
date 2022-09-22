import os, datetime

if not os.path.exists('nist-mirror'):
    os.makedirs('nist-mirror')

for year in range(2002, datetime.date.today().year + 1):
    print('nvdcve-1.1-{}.json.gz'.format(year))
    os.system('curl -o nist-mirror/nvdcve-1.1-{}.json.gz https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz'.format(year, year))

# os.system('curl -o vullist_1.csv https://bdu.fstec.ru/files/documents/vullist.xlsx')
