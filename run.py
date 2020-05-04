#!/usr/bin/env python3

import os.path
import lib.check as domain
import csv

domainsList = 'config/domains.txt'
domainsTsv = 'config/domains.tsv'

if not os.path.isfile(domainsList):
    print('Veuillez creer le fichier ' + domainsList)
    exit()

if os.path.isfile(domainsTsv):
    os.remove(domainsTsv)

with open(domainsTsv, mode='w') as csv_file:
    writer = csv.writer(csv_file, delimiter="\t", quotechar='"', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(domain.header())

    with open(domainsList) as lines:
        for line in lines:
            line = line.strip()

            if '' == line:
                continue

            writer.writerow(domain.check(line))

            if not line.startswith('www.') and 1 == line.count('.'):
                writer.writerow(domain.check('www.' + line))
