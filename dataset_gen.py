import ssl
import datetime
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen
import tqdm
import pandas as pd
import warnings
warnings.filterwarnings("ignore")


ssl._create_default_https_context = ssl._create_unverified_context


def main():
    url = "https://us-cert.cisa.gov/ics/advisories?items_per_page=All"

    hdr = {
        'User-Agent': 'Mozilla/5.0'
    }

    req = Request(url, headers=hdr)
    page = urlopen(req)
    soup = BeautifulSoup(page)

    list_of_advisories = soup.findAll('li')

    all_advisories = {}
    for advisory in tqdm.tqdm(list_of_advisories[6:], desc='Collecting advisories'):
        all_advisories[advisory.span.span.text] = {}
        all_advisories[advisory.span.span.text]['URL'] = 'https://us-cert.cisa.gov/' + advisory.a['href']

        icsa_req = Request(all_advisories[advisory.span.span.text]['URL'], headers=hdr)
        icsa_page = urlopen(icsa_req)
        icsa_soup = BeautifulSoup(icsa_page)

        try:
            year = advisory.span.span.text.split('-')[1]
        except IndexError:
            year = advisory.span.span.text.split()[-1]
        all_advisories[advisory.span.span.text]['YEAR'] = year

        all_a = icsa_soup.body.article.findAll('a', href=True)
        all_p = icsa_soup.body.article.findAll('p')

        all_cves = []
        all_cves.extend([x.text for x in all_a if 'cve' in x.text.lower()])

        for p in all_p:
            if 'cve' in p.text.lower():
                cve_found = p.text.find("CVE")
                if cve_found >= 0:
                    cves = p.text[cve_found:].split()
                    for c in cves:
                        if "CVE-" in c:
                            all_cves.append(c.replace('.', ""))

        all_cves = list(set(all_cves))
        all_advisories[advisory.span.span.text]['CVES'] = all_cves

        all_cves_url = []
        all_cves_url.extend([x['href'] for x in all_a if 'cve' in x.text.lower()])
        all_advisories[advisory.span.span.text]['CVES_URL'] = all_cves_url

        all_li = []
        for ul in icsa_soup.body.article.findAll('ul'):
            all_li.extend(ul.findAll('li'))

        try:
            for li in all_li:
                if "attention" in li.text.lower():
                    attention = li.text.replace("ATTENTION: ", "")
        except (IndexError, NameError, AttributeError):
            attention = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['ATTENTION'] = attention

        try:
            for li in all_li:
                if "vendor" in li.text.lower():
                    vendor = li.text.replace("Vendor: ", "")
        except:
            vendor = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['VENDOR'] = vendor

        try:
            for li in all_li:
                if "equipment" in li.text.lower():
                    equipment = li.text.replace("Equipment: ", "")
        except (IndexError, AttributeError):
            equipment = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['EQUIPMENT'] = equipment

        try:
            for li in all_li:
                if "vulnerabilities" in li.text.lower():
                    vulnerabilities = li.text.replace("Vulnerabilities: ", "")
                else:
                    vulnerabilities = 'Not Found'
        except (IndexError, AttributeError):
            vulnerabilities = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['VULNERABILITIES'] = vulnerabilities

        try:
            for li in all_li:
                if 'CRITICAL INFRASTRUCTURE SECTORS'.lower() in li.text.lower():
                    critical_infraestructure_sector = li.text.replace('CRITICAL INFRASTRUCTURE SECTORS:', "")
        except IndexError:
            critical_infraestructure_sector = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['CRITICAL INFRAESTRUCTURE SECTOR'] = critical_infraestructure_sector

        try:
            for li in all_li:
                if "COUNTRIES/AREAS DEPLOYED".lower() in li.text.lower():
                    countries_areas_deployed = li.text.replace('COUNTRIES/AREAS DEPLOYED: ', "")
        except IndexError:
            countries_areas_deployed = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['COUNTRIES\/AREAS DEPLOYED'] = countries_areas_deployed

        try:
            for li in all_li:
                if "COMPANY HEADQUARTERS LOCATION".lower() in li.text.lower():
                    company_headquarters_location = li.text.replace('COMPANY HEADQUARTERS LOCATION: ', "")
        except IndexError:
            company_headquarters_location = "Not Found"
        finally:
            all_advisories[advisory.span.span.text]['COMPANY HEADQUARTERS LOCATION'] = company_headquarters_location

        try:
            cwes = []
            for cwe in icsa_soup.body.article.findAll('h4'):
                if 'cwe' in cwe.text.lower():
                    cwes.append(cwe.text.split()[-1].split('-')[1])
        except IndexError:
            cwes = "Not Found"

        all_advisories[advisory.span.span.text]['CWES'] = cwes

    df = pd.DataFrame.from_dict(all_advisories)
    df = df.T.reset_index()
    df.rename(columns={'index': 'icsa_code'}, inplace=True)
    df.loc[df['YEAR'] == '2011', 'YEAR'] = '11'
    timestamp = "{:%Y-%b-%d %H:%M:%S}".format(datetime.datetime.now())
    df.to_csv(f'data/icsa_{timestamp}.csv')


if __name__ == '__main__':
    main()
