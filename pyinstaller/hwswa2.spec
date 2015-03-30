# -*- mode: python -*-
a = Analysis(['hwswa2.py'],
             pathex=[],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
a.datas += [('wagent.exe','resources/wagent.exe','DATA'),
            ('wagent-debug.exe','resources/wagent-debug.exe','DATA')]
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
