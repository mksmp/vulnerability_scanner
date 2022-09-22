import argparse
import re
import gzip
import json
from packaging import version

url = "nist-mirror/nvdcve-1.1-{YEAR}.json.gz"
args = None
short = None
count = -1

CVEs = list()


def shorten():
    i = len(CVEs)
    for entry in CVEs:
        print(f'''{entry['cve']['CVE_data_meta']['ID']} Level:{entry['impact']['baseMetricV2']['severity']} {entry['cve']['description']['description_data'][0]['value']}'''
              )

        i -= 1


def search(j, s, v): # j-json, s-name of service, v-version of service
    i = 0
    regex = re.compile(f'({s})', re.I)
    for entry in j['CVE_Items']:
        if 'cve' in entry:
            desc = entry['configurations']['nodes']
            for d in desc:
                for cpe in d['cpe_match']:
                    if regex.search(cpe['cpe23Uri']) != None:
                        if 'versionEndExcluding' in cpe and version.parse(v) < version.parse(cpe['versionEndExcluding']):
                            if 'versionStartExcluding' in cpe and version.parse(v) > version.parse(cpe['versionStartExcluding']):
                                CVEs.append(entry)
                                i += 1
                                break
                            else:
                                CVEs.append(entry)
                                i += 1
                                break
        if i == count:
            break

    if short:
        shorten()
    return


def search_cve():
    global args, short

    p = argparse.ArgumentParser()
    p.add_argument('-s', '--short', default=False,
                   help="Print short version of each CVE entry", action='store_true')

    p.add_argument('search', type=str, help="Search query (regex capable)")
    p.add_argument('version', type=str, help="Search version")

    args = p.parse_args()

    short = args.short
    years = range(2002, 2022)

    for year in years:

        try:
            ff = url.replace('{YEAR}', str(year))
            with open(ff, 'rb') as my_file:
                data = json.loads(gzip.decompress(my_file.read()))
        except json.decoder.JSONDecodeError:
            raise Exception("Error decoding NIST JSON")
        search(data, args.search, args.version)

    if len(CVEs) > 0 and not short:
        print(json.dumps(CVEs))
    my_file.close()


if __name__ == '__main__':
    search_cve()
