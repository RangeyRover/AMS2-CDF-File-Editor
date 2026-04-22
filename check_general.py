import xml.etree.ElementTree as ET

tree = ET.parse('../cdf-hex-map.xml')
blocks = tree.getroot().find('parameters').findall('.//group[@name="General"]/block')
print(f"Total blocks in 'General' groups: {len(blocks)}")
for b in blocks[:50]:
    print(b.attrib['name'], b.attrib['signature'])
