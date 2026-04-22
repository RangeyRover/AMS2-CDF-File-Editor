import xml.etree.ElementTree as ET

tree = ET.parse('../cdf-hex-map.xml')
for sec in tree.getroot().find('parameters'):
    for grp in sec:
        for blk in grp:
            if blk.attrib['name'] == 'FRWAft':
                print(f"FRWAft is in Section: {sec.attrib['name']}, Group: {grp.attrib['name']}")
