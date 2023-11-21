# Cryptographic-Files

---

<br>

Encrypt and Decrypt files and directories using`cryptography` python library with built in GUI by `tkinter`

Please be mindful of the salt file which should be stored separtely from the encrypted files, it is the 2nd factor in authenticating the encrypted data. If you lose this key, your data will be nearly impossible to access once encrypted. Likewise, choose a suitable password and store it separately from the salt.

how to use:

```zsh
pip install requirements.txt
```
 <sub> it is likely you may need to use `pip3` if on a mac instead of `pip`</sub> 


```zsh
python crypto.py
```
 <sub> it is likely you may need to use `python3` if on a mac instead of `python`</sub> 