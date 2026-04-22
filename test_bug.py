import cdf_parser
defs = cdf_parser.load_dictionary()
print('Loaded defs:', len(defs))

import glob
cdf_files = glob.glob('../*.cdfbin') + glob.glob('*.cdfbin')
if cdf_files:
    blob = open(cdf_files[0], 'rb').read()
    insts = cdf_parser.parse_cdfbin(blob, defs)
    print('Found insts:', len(insts))
else:
    print('No cdfbin files found to test.')
