# 2FA

A command-line generator of Time-based One-time Password (TOTP) for Two-Factor Authentication (2FA) written in Python3 and Go lang (two identical versions). Reduced from [py2fa](https://github.com/cpiehl/py2fa) which offers a graphical (Gtk) user interface.


```bash
# Edit/create a json file similar to sample.my2fa.json to fit your needs; 
# the json format is self-explainatory.
# For the python version run
./2fa.py -j sample.my2fa.json
# For options
./2fa.py -h
# For the Go-lang version
go build 2fa.go
./2fa -json sample.my2fa.json
./2fa -h
```
