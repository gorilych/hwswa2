# -*- mode: python -*-
a = Analysis(['hwswa2/main.py'],
             pathex=['libs/', 'pyinstaller/'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
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
