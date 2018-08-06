# FAQueue
Actual documentation incoming at some point.

```shell
pyvenv-3.4 --without-pip venv
source ./venv/bin/activate
wget https://pypi.python.org/packages/source/s/setuptools/setuptools-3.4.4.tar.gz
tar -zxvf setuptools-3.4.4.tar.gz 
cd setuptools-3.4.4/
python setup.py install
cd ..
wget https://pypi.python.org/packages/source/p/pip/pip-1.5.6.tar.gz
tar -zxvf pip-1.5.6.tar.gz 
cd pip-1.5.6/
python setup.py install
cd ../
deactivate
rm -rf setuptools-3.4.4*
rm -rf pip-1.5.6*
```

If you have gpg encryption on email archive files, you'll need to import the keys:
gpg --import etc/keys/whatever.pub
gpg --allow-secret-key-import --import etc/keys/whatever.key
