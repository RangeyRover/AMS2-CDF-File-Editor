import xml.etree.ElementTree as ET

tree = ET.parse('../cdf-hex-map.xml')
notes = tree.getroot().findall('.//notes')
print("--- Multiline Notes ---")
multiline_notes = [n.text for n in notes if n.text and '\n' in n.text]
for text in multiline_notes[:5]:
    print(text)
    print("-----")
