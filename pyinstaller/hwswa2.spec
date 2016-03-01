# -*- mode: python -*-

import pkg_resources

a = Analysis(['../hwswa2.py'],
             pathex=[],
             hiddenimports=['_cffi_backend'],
             hookspath=None,
             runtime_hooks=None)

pyz = PYZ(a.pure)

for fn in ('adjacency_graphs.json', 'frequency_lists.json'):
     a.datas.append(('zxcvbn/generated/' + fn,
                pkg_resources.resource_filename('zxcvbn', 'generated/' + fn),
                'DATA'))

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='hwswa2',
          debug=False,
          strip=True,
          upx=True,
          console=True )
