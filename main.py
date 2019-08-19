#!/usr/bin/env python
import os
import re
import subprocess
import sys

import DXA

from xml.sax.saxutils import quoteattr # Escape " and ' in XML

def generate_new_DXA(last_DLA, last_DSA):
    DXA_array = list()
    first_DLA = ""
    first = True

    #import pdb; pdb.set_trace()
    with open('security-tracker/data/DLA/list') as DLA_file:
        for line in DLA_file:
            if last_DLA in line:  # add only new DLA
                break
            try:
                DLA_name = re.search('DLA-[0-9]*-[0-9]*', line).group(0)
                if first:
                    first_DLA = DLA_name
                    first = False
                DLA_date = re.search(r'^\[([^\]]*)\]*', line).group(1)
                DLA_soft = re.match(r'\[.*\] DLA-[0-9\-]* (.*) -.*', line).group(1)
                DLA_soft = DLA_soft.replace(" ", "")
                DLA_syno = re.search(" - (.*)$", line).group(1)
                nex = next(DLA_file)  # Look next line of file for corresponding CVE
                CVE_names = re.findall(r'CVE-[0-9]*-[0-9]*', nex)
                DLA_synopsys = DLA_soft + " -- " + DLA_syno
                # Add new object to DLA array
                DXA_array.append(DXA.DXA('DLA', DLA_name, DLA_soft, DLA_date, CVE_names, DLA_synopsys))
            except AttributeError:  # Regex will not always match
                pass

    first_DSA = ""
    first = True
    with open("security-tracker/data/DSA/list", "r") as DSA_file:
            for line in DSA_file:
                if last_DSA in line:
                    break
                try:
                    DSA_name = re.search('DSA-[0-9]*-[0-9]*', line).group(0)
                    if first:
                        first_DSA = DSA_name
                        first = False
                    DSA_date = re.search(r'^\[([^\]]*)\]*', line).group(1)
                    DSA_soft = re.match(r'\[.*\] DSA-[0-9\-]* (.*) -.*', line).group(1)
                    DSA_soft.replace(" ", "")
                    DLA_syno = re.search(" - (.*)$", line).group(1)
                    DSA_syno = re.search(" - (.*)$", line).group(1)
                    nex = next(DSA_file)  # Look next line of file for corresponding CVE
                    CVE_names = re.findall(r'CVE-[0-9]*-[0-9]*', nex)
                    DSA_synopsys = DSA_soft + " -- " + DSA_syno
                    # Add new object to DLA array
                    DXA_array.append(DXA.DXA('DSA', DSA_name, DSA_soft, DSA_date, CVE_names, DSA_synopsys))
                except AttributeError:  # Regex will not always match
                    pass
    return DXA_array, first_DLA, first_DSA

def create_xml_file(DXA_array):
    with open('XML', 'a') as xml_file:
        xml_file.write('<?xml version="1.0"?>\n')
        xml_file.write('<opt>\n')
        for dxa in DXA_array:
            to_write = '  <' + dxa.name + ' description=' + quoteattr(dxa.description) \
                + ' from="Debian CVS english security report" multirelease="1" notes=' \
                + quoteattr(dxa.notes) + ' product="Debian Linux" references=' \
                + quoteattr(dxa.link) + ' release="1" solution="Not available" synopsis=' \
                + quoteattr(dxa.synopsys) + ' topic=' + quoteattr(dxa.synopsys) \
                + ' type="Security Advisory" security_name=' + quoteattr(dxa.name) + '>\n'
            xml_file.write(to_write)
            if dxa.packages:
                for pack in dxa.packages:
                    for version in dxa.versions:
                        to_write = '    <packages>' + pack + '-' + version + '.amd64-deb.deb</packages>\n'
                        xml_file.write(to_write)
            if dxa.CVE:
                for cve in dxa.CVE:
                    to_write = '    <cves>' + cve + '</cves>\n'
                    xml_file.write(to_write)
                
            to_write = '  </' + dxa.name + '>\n'    
            xml_file.write(to_write)
        xml_file.write('</opt>\n')

def write_last_DXA(first_DLA, first_DSA):
    # Format : text, like
    # DSA-2019-12
    # DLA-2019-13   
    # Conserve last 2 versions
    to_write = last_DLA + " " + last_DSA + "\n"
    with open('last_DXA', 'w') as last_DXA:
        last_DXA.write(to_write)

def get_latest_DXA():
    """
    Parse text file last_DXA and return latest DLA and DSA name
    File content example :
        DLA-1708-1 DSA-4405-1
    Out :
        String last_DLA
        String last_DSA
    """

    if os.path.isfile('last_DXA'):
        with open('last_DXA') as last_DXA:
            lines = last_DXA.read().split()
    else:
        print("Missing file 'last_DXA' !")
        sys.exit(1)
    if len(lines) == 2:
        if "DLA" in lines[0] and "DSA" in lines[1]:
            return lines[0], lines[1]

    # No need to add if condition because of return
    print("File last_DXA malformed")
    sys.exit(1)
            
        
if __name__ == '__main__':
    """
    """

    # TODO : add condition to check if git pull succeed
    if os.path.isfile("XML"):
        os.rename("XML", "XML.bak")
        
    last_DLA, last_DSA = get_latest_DXA()
    out = subprocess.check_output(['git', 'pull'], cwd="security-tracker")
    DXA_array, up_last_DLA, up_last_DSA = generate_new_DXA(last_DLA, last_DSA)
    create_xml_file(DXA_array)
    if up_last_DLA and up_last_DSA:
        write_last_DXA(up_last_DLA, up_last_DSA)
    elif up_last_DLA and not up_last_DSA:
        write_last_DXA(up_last_DLA, last_DSA)
    elif not up_last_DLA and up_last_DSA:
        write_last_DXA(last_DLA, up_last_DSA)


