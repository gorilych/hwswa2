#!/bin/bash

# example of build script

set -e

HWSWA2dir=/home/akartashov/hwswa2/build/hwswa2

pushd ${HWSWA2dir}

git pull

which rst2pdf >/dev/null && \
{ for d in README.rst CHANGELOG.rst docs/*rst; do rst2pdf $d; done; }

[ -d env ] || virtualenv --python=/usr/bin/python2 --no-site-packages --prompt='(hwswa2)' env

source env/bin/activate

pip install -r requirements.txt

rm -rf pyinstaller/hwswa2 pyinstaller/hwswa2.tgz
pyinstaller --distpath=pyinstaller/hwswa2/ --workpath=pyinstaller/build/ \
            --clean pyinstaller/hwswa2.spec

cp -af README* LICENSE CHANGELOG* config/ roles/ resources/ docs/ \
       pyinstaller/hwswa2/

pushd pyinstaller/
tar zcf hwswa2.tgz hwswa2
popd

sudo rm -rf /usr/local/share/hwswa2/* && tar zxf ${HWSWA2dir}/pyinstaller/hwswa2.tgz -C /usr/local/share/

popd

scp ${HWSWA2dir}/pyinstaller/hwswa2.tgz me@gorilych.ru:/var/www/gorilych.ru/me/

echo local copy ${HWSWA2dir}/pyinstaller/hwswa2.tgz
echo download from http://gorilych.ru/me/hwswa2.tgz

